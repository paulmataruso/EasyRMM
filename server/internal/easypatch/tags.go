package easypatch

// EasyPatch's tags, from EasyRMM (one-product plan, C4). Tags are shared by
// every organization, and a tag's policy can change any of them, so EasyPatch
// lets only administrators without organization restrictions manage or
// assign them; in EasyRMM that is whoever may configure patching everywhere
// (super administrators). Anyone who sees patching sees the tags in use in
// their organizations.

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"unicode"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// TagColors are the colors a tag can have.
var TagColors = []string{"gray", "blue", "green", "amber", "red", "purple", "teal", "pink"}

// maxTags is how many tags an organization, site or device can have.
const maxTags = 20

// TagList is the tags the caller sees.
type TagList struct {
	Items []Tag `json:"items"`
	// CanManage says the caller may add, change and delete tags and their
	// policies.
	CanManage bool `json:"canManage"`
}

// AssignedTags are an organization's, site's or device's tags.
type AssignedTags struct {
	// Tags are the object's own tags and, for a device, those it has through
	// its site or organization (InheritedFrom).
	Tags      []TagRef `json:"tags"`
	CanAssign bool     `json:"canAssign"`
}

// canManageTags says the caller may add, change and delete tags and their
// policies, and change an organization's, site's or device's tags: the
// engine keeps tags to its super administrators.
func (s *Service) canManageTags(c access.Caller) bool { return c.CanGlobal(rbac.PermPatchConfigure) }

// manageTags checks that the caller may add, change or delete tags.
func (s *Service) manageTags(c access.Caller) error {
	if !s.canManageTags(c) {
		return apperr.Forbidden()
	}
	return nil
}

// Tags lists the tags: every one for someone who sees patching everywhere,
// those in use in their organizations for anyone else.
func (s *Service) Tags(ctx context.Context, c access.Caller) (TagList, error) {
	r, cl, err := s.conn(ctx)
	if err != nil {
		return TagList{}, err
	}
	if r == nil {
		return TagList{}, errNotConfigured
	}
	if !c.CanAnywhere(rbac.PermPatchView) {
		return TagList{}, apperr.Forbidden()
	}
	rctx := s.everywhere(ctx, c, RoleReadOnly)
	if !c.CanGlobal(rbac.PermPatchView) {
		linked, err := s.linkedOrgs(ctx, c)
		if err != nil {
			return TagList{}, err
		}
		orgs := make([]uuid.UUID, 0, len(linked))
		for ep := range linked {
			orgs = append(orgs, ep)
		}
		if len(orgs) == 0 {
			return TagList{Items: []Tag{}}, nil
		}
		rctx = s.as(ctx, c, RoleReadOnly, orgs...)
	}
	tags, err := cl.Tags(rctx)
	if err != nil {
		s.noteError(err)
		return TagList{}, epError(err)
	}
	return TagList{Items: orEmpty(tags), CanManage: s.canManageTags(c)}, nil
}

// normalizeTag checks a tag as EasyPatch does.
func normalizeTag(in *TagInput) error {
	f := apperr.Fields{}
	in.Name = strings.TrimSpace(in.Name)
	f.Check(in.Name != "" && len([]rune(in.Name)) <= 40, "name", "Give a name of 1 to 40 characters.")
	f.Check(!strings.ContainsFunc(in.Name, unicode.IsControl), "name", "Give a name without control characters.")
	f.Check(slices.Contains(TagColors, in.Color), "color", "Choose one of the colors.")
	f.Check(in.Priority >= 0 && in.Priority <= 1000, "priority", "Choose a priority from 0 to 1000.")
	if in.Description != nil {
		d := strings.TrimSpace(*in.Description)
		f.Check(len([]rune(d)) <= 500, "description", "Keep the description to 500 characters.")
		in.Description = &d
		if d == "" {
			in.Description = nil
		}
	}
	return f.Err()
}

var errTagExists = apperr.Invalid("name", "A tag with this name already exists.")

// CreateTag adds a tag.
func (s *Service) CreateTag(ctx context.Context, c access.Caller, in TagInput) (Tag, error) {
	_, cl, err := s.operable(ctx)
	if err != nil {
		return Tag{}, err
	}
	if err := s.manageTags(c); err != nil {
		return Tag{}, err
	}
	if err := normalizeTag(&in); err != nil {
		return Tag{}, err
	}
	t, err := cl.CreateTag(s.everywhere(ctx, c, RoleSuperAdmin), in, c.Actor.Label)
	if err != nil {
		if IsStatus(err, http.StatusConflict) {
			return Tag{}, errTagExists
		}
		s.noteError(err)
		return Tag{}, epError(err)
	}
	return t, s.recordTag(ctx, c, "patch.tag_create", t.ID, map[string]any{"name": t.Name, "color": t.Color, "priority": t.Priority})
}

// UpdateTag changes a tag's name, color, description or priority.
func (s *Service) UpdateTag(ctx context.Context, c access.Caller, id uuid.UUID, in TagInput) (Tag, error) {
	_, cl, err := s.operable(ctx)
	if err != nil {
		return Tag{}, err
	}
	if err := s.manageTags(c); err != nil {
		return Tag{}, err
	}
	if err := normalizeTag(&in); err != nil {
		return Tag{}, err
	}
	before, err := s.tag(ctx, c, cl, id)
	if err != nil {
		return Tag{}, err
	}
	t, err := cl.UpdateTag(s.everywhere(ctx, c, RoleSuperAdmin), id, in, c.Actor.Label)
	switch {
	case IsStatus(err, http.StatusNotFound):
		return Tag{}, apperr.NotFound()
	case IsStatus(err, http.StatusConflict):
		return Tag{}, errTagExists
	case err != nil:
		s.noteError(err)
		return Tag{}, epError(err)
	}
	details := map[string]any{"name": t.Name}
	if before.Name != t.Name {
		details["renamedFrom"] = before.Name
	}
	if before.Priority != t.Priority {
		details["priority"] = fmt.Sprintf("%d → %d", before.Priority, t.Priority)
	}
	if before.Color != t.Color {
		details["color"] = t.Color
	}
	s.fleet.clear()
	return t, s.recordTag(ctx, c, "patch.tag_update", id, details)
}

// DeleteTag removes a tag, its policy and every assignment of it.
func (s *Service) DeleteTag(ctx context.Context, c access.Caller, id uuid.UUID) error {
	_, cl, err := s.operable(ctx)
	if err != nil {
		return err
	}
	if err := s.manageTags(c); err != nil {
		return err
	}
	t, err := s.tag(ctx, c, cl, id)
	if err != nil {
		return err
	}
	err = cl.DeleteTag(s.everywhere(ctx, c, RoleSuperAdmin), id, c.Actor.Label)
	switch {
	case IsStatus(err, http.StatusNotFound):
		return apperr.NotFound()
	case err != nil:
		s.noteError(err)
		return epError(err)
	}
	s.fleet.clear()
	return s.recordTag(ctx, c, "patch.tag_delete", id, map[string]any{"name": t.Name, "devices": t.EndpointCount, "hadPolicy": t.HasPolicy})
}

// tag reads one tag.
func (s *Service) tag(ctx context.Context, c access.Caller, cl *Client, id uuid.UUID) (Tag, error) {
	tags, err := cl.Tags(s.everywhere(ctx, c, RoleReadOnly))
	if err != nil {
		s.noteError(err)
		return Tag{}, epError(err)
	}
	i := slices.IndexFunc(tags, func(t Tag) bool { return t.ID == id })
	if i < 0 {
		return Tag{}, apperr.NotFound()
	}
	return tags[i], nil
}

func (s *Service) recordTag(ctx context.Context, c access.Caller, action string, id uuid.UUID, details map[string]any) error {
	return s.record(ctx, []audit.Event{{Actor: c.Actor, Action: action, TargetType: "patch_tag", TargetID: id.String(),
		Outcome: audit.Success, Details: details}})
}

// AssignedTags reads an organization's, site's or device's tags.
func (s *Service) AssignedTags(ctx context.Context, c access.Caller, level string, id uuid.UUID) (AssignedTags, error) {
	r, cl, err := s.conn(ctx)
	if err != nil {
		return AssignedTags{}, err
	}
	if r == nil {
		return AssignedTags{}, errNotConfigured
	}
	if level != LevelOrganization && level != LevelSite && level != LevelDevice {
		return AssignedTags{}, errTagLevel
	}
	t, err := s.policyTarget(ctx, c, cl, level, id, false)
	if err != nil {
		return AssignedTags{}, err
	}
	tags, err := s.assigned(s.as(ctx, c, RoleReadOnly, t.epOrg), cl, t)
	if err != nil {
		s.noteError(err)
		return AssignedTags{}, epError(err)
	}
	return AssignedTags{Tags: tags, CanAssign: s.canManageTags(c)}, nil
}

var errTagLevel = apperr.Invalid("level", "Choose organization, site or device.")

func (s *Service) assigned(ctx context.Context, cl *Client, t policyTarget) ([]TagRef, error) {
	var tags []TagRef
	switch t.level {
	case LevelOrganization:
		o, err := cl.GetOrganization(ctx, t.epID)
		if err != nil {
			return nil, err
		}
		tags = o.Tags
	case LevelSite:
		st, err := cl.GetSite(ctx, t.epID)
		if err != nil {
			return nil, err
		}
		tags = st.Tags
	default:
		e, err := cl.Endpoint(ctx, t.epID)
		if err != nil {
			return nil, err
		}
		tags = e.Summary.Tags
	}
	return orEmpty(tags), nil
}

// SetTags replaces an organization's, site's or device's own tags.
func (s *Service) SetTags(ctx context.Context, c access.Caller, level string, id uuid.UUID, ids []uuid.UUID) (AssignedTags, error) {
	_, cl, err := s.operable(ctx)
	if err != nil {
		return AssignedTags{}, err
	}
	if level != LevelOrganization && level != LevelSite && level != LevelDevice {
		return AssignedTags{}, errTagLevel
	}
	t, err := s.policyTarget(ctx, c, cl, level, id, false)
	if err != nil {
		return AssignedTags{}, err
	}
	if !s.canManageTags(c) {
		return AssignedTags{}, apperr.Forbidden()
	}
	want := dedupe(ids)
	if len(want) > maxTags {
		return AssignedTags{}, apperr.Invalid("tagIds", fmt.Sprintf("Give at most %d tags.", maxTags))
	}
	all, err := cl.Tags(s.everywhere(ctx, c, RoleReadOnly))
	if err != nil {
		s.noteError(err)
		return AssignedTags{}, epError(err)
	}
	names := map[uuid.UUID]string{}
	for _, tg := range all {
		names[tg.ID] = tg.Name
	}
	for _, id := range want {
		if _, ok := names[id]; !ok {
			return AssignedTags{}, apperr.Invalid("tagIds", "Choose tags that exist; one was deleted.")
		}
	}
	rctx := s.as(ctx, c, RoleReadOnly, t.epOrg)
	before, err := s.assigned(rctx, cl, t)
	if err != nil {
		s.noteError(err)
		return AssignedTags{}, epError(err)
	}
	var added, removed []string
	own := []uuid.UUID{}
	for _, tg := range before {
		if tg.InheritedFrom == "" {
			own = append(own, tg.ID)
			if !slices.Contains(want, tg.ID) {
				removed = append(removed, tg.Name)
			}
		}
	}
	for _, id := range want {
		if !slices.Contains(own, id) {
			added = append(added, names[id])
		}
	}
	if len(added) > 0 || len(removed) > 0 {
		if err := cl.SetTags(s.everywhere(ctx, c, RoleAdmin), t.kind, t.epID, want, c.Actor.Label); err != nil {
			s.noteError(err)
			return AssignedTags{}, epError(err)
		}
		ev := audit.Event{Actor: c.Actor, Action: "patch.tag_assign", TargetType: t.targetType, TargetID: t.targetID.String(),
			OrganizationID: t.org, Outcome: audit.Success,
			Details: map[string]any{"name": t.name, "added": orEmpty(added), "removed": orEmpty(removed)}}
		if err := s.record(ctx, []audit.Event{ev}); err != nil {
			return AssignedTags{}, err
		}
		s.fleet.clear()
	}
	after, err := s.assigned(rctx, cl, t)
	if err != nil {
		s.noteError(err)
		return AssignedTags{}, epError(err)
	}
	return AssignedTags{Tags: after, CanAssign: true}, nil
}
