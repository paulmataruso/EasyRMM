package registry

import (
	"errors"
	"strings"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/internal/registryrules"
)

// stop ends a walk at a bound: it names the bound and the first key the walk
// did not visit.
type stop struct{}

func (stop) Error() string { return "the walk stopped at a bound" }

// bound records which bound stopped a walk, and the first key it did not
// visit.
func (e *engine) bound(by string, path []string) error {
	if e.end.StoppedBy == "" {
		e.end.StoppedBy = by
		e.end.FirstUnvisited = nonNil(path)
	}
	return stop{}
}

// childOpen opens a child of a key in a walk. ok is false for a child the
// walk leaves alone, with the state to say why: a refused key is never
// opened, a link is not followed, a denied key is left out.
func (e *engine) childOpen(parent Key, path []string, name string) (child Key, state, target, rule string) {
	if r := registryrules.CheckWith(registryrules.Hive(e.in.Hive), e.view, path, e.extra); r != nil {
		return nil, agentproto.StateRefused, "", r.Rule
	}
	c, err := parent.OpenChild(name)
	if err != nil {
		return nil, agentproto.StateDenied, "", ""
	}
	if f := e.kernelRefusal(c); f != nil {
		c.Close()
		return nil, agentproto.StateRefused, "", f.refusal.Rule
	}
	if h := registryrules.Hive(e.in.Hive); len(path) == 1 && (h == registryrules.HKLM || h == registryrules.HKU) {
		if f := e.mountedCopy(h, name, c); f != nil {
			c.Close()
			return nil, agentproto.StateRefused, "", f.refusal.Rule
		}
	}
	if t, ok := c.LinkTarget(); ok {
		c.Close()
		return nil, agentproto.StateLink, agentproto.SafeText(t), ""
	}
	return c, "", "", ""
}

// search looks from the opened key down to a depth, for key names, value
// names and string data that hold the term, ordinal and ignoring case. It
// never enters a refused key, never follows a link, and never looks inside
// masked data.
func (e *engine) search(root Key) error {
	term := registryrules.Fold(e.in.Term)
	depth, maxMatches := e.in.Depth, e.in.MaxMatches
	if depth == 0 {
		depth = agentproto.RegDefaultDepth
	}
	if maxMatches == 0 {
		maxMatches = agentproto.RegMaxMatches
	}
	visited := 0
	var visit func(k Key, path []string, d int) error
	visit = func(k Key, path []string, d int) error {
		if e.expired() {
			return e.bound(agentproto.StoppedTime, path)
		}
		if visited >= agentproto.RegMaxVisited {
			return e.bound(agentproto.StoppedKeys, path)
		}
		visited++
		e.end.Visited = visited
		match := func(m agentproto.RegMatch) error {
			if e.end.Matches >= maxMatches {
				return e.bound(agentproto.StoppedMatches, path)
			}
			if err := e.w.put(m); err != nil {
				return err
			}
			e.end.Matches++
			return nil
		}
		if vals, err := k.ValueNames(); err == nil {
			order(vals)
			for _, name := range vals {
				if registryrules.ValidateValueName(name) != nil {
					continue
				}
				if strings.Contains(registryrules.Fold(name), term) {
					if err := match(agentproto.RegMatch{T: agentproto.LineMatch, Kind: agentproto.MatchValueName, Path: nonNil(path), Name: name}); err != nil {
						return err
					}
				}
				typ, size, err := k.ValueInfo(name)
				if err != nil || size > 64<<10 || registryrules.IsMasked(name, typ) {
					continue
				}
				if typ != registryrules.TypeSZ && typ != registryrules.TypeExpandSZ && typ != registryrules.TypeMultiSZ {
					continue
				}
				_, data, err := k.ReadValue(name)
				if err != nil {
					continue
				}
				v := agentproto.EncodeRegValue(name, typ, data, false, false, 64<<10)
				hit := v.Text != nil && strings.Contains(registryrules.Fold(*v.Text), term)
				for _, it := range v.Items {
					hit = hit || strings.Contains(registryrules.Fold(it), term)
				}
				if hit {
					if err := match(agentproto.RegMatch{T: agentproto.LineMatch, Kind: agentproto.MatchData, Path: nonNil(path), Name: name, Type: typ}); err != nil {
						return err
					}
				}
			}
		}
		if d >= depth {
			return nil
		}
		subs, err := k.SubkeyNames()
		if err != nil {
			return nil //nolint:nilerr // a key that cannot be listed is left out; the walk goes on
		}
		order(subs)
		for _, name := range subs {
			if registryrules.ValidateName(name) != nil {
				continue
			}
			child := append(append([]string{}, path...), name)
			if strings.Contains(registryrules.Fold(name), term) {
				if r := registryrules.CheckWith(registryrules.Hive(e.in.Hive), e.view, child, e.extra); r == nil {
					if err := match(agentproto.RegMatch{T: agentproto.LineMatch, Kind: agentproto.MatchKey, Path: child}); err != nil {
						return err
					}
				}
			}
			c, state, target, _ := e.childOpen(k, child, name)
			switch {
			case state == agentproto.StateLink:
				if err := match(agentproto.RegMatch{T: agentproto.LineMatch, Kind: agentproto.MatchLink, Path: child, Name: target}); err != nil {
					return err
				}
				continue
			case c == nil:
				continue
			}
			err := visit(c, child, d+1)
			c.Close()
			if err != nil {
				return err
			}
		}
		return nil
	}
	err := visit(root, nonNil(e.in.Path), 0)
	if errors.Is(err, stop{}) {
		return nil
	}
	return err
}

// export writes a key and its subtree, with every value, up to 5,000 keys
// and the result file's size. A key that is refused, a link and a key
// Windows denied are written as such, with no data, so that importing the
// file never makes a link and says what was left out.
func (e *engine) export(root Key) error {
	keys := 0
	var visit func(k Key, path []string) error
	visit = func(k Key, path []string) error {
		if e.expired() {
			return e.bound(agentproto.StoppedTime, path)
		}
		if keys >= agentproto.RegMaxExportKeys {
			return e.bound(agentproto.StoppedExported, path)
		}
		keys++
		line := agentproto.RegXKey{T: agentproto.LineXKey, Path: nonNil(path)}
		if info, err := k.Info(); err == nil {
			line.LastWrite = stamp(info.LastWrite)
		}
		if vals, err := k.ValueNames(); err == nil {
			order(vals)
			for _, name := range vals {
				if registryrules.ValidateValueName(name) != nil {
					line.Left = append(line.Left, "value left out, its name is not valid text")
					continue
				}
				line.Values = append(line.Values, e.exportValue(k, name))
			}
		}
		if err := e.w.put(line); err != nil {
			if errors.Is(err, errFull) {
				return e.bound(agentproto.StoppedSize, path)
			}
			return err
		}
		e.end.Visited = keys
		subs, err := k.SubkeyNames()
		if err != nil {
			return nil //nolint:nilerr // left out; the walk goes on
		}
		order(subs)
		for _, name := range subs {
			if registryrules.ValidateName(name) != nil {
				continue
			}
			child := append(append([]string{}, path...), name)
			c, state, target, rule := e.childOpen(k, child, name)
			if c == nil {
				if keys >= agentproto.RegMaxExportKeys {
					return e.bound(agentproto.StoppedExported, child)
				}
				keys++
				x := agentproto.RegXKey{T: agentproto.LineXKey, Path: child, State: state, Target: target, Rule: rule}
				if err := e.w.put(x); err != nil {
					if errors.Is(err, errFull) {
						return e.bound(agentproto.StoppedSize, child)
					}
					return err
				}
				continue
			}
			err := visit(c, child)
			c.Close()
			if err != nil {
				return err
			}
		}
		return nil
	}
	err := visit(root, nonNil(e.in.Path))
	if errors.Is(err, stop{}) {
		return nil
	}
	return err
}

// exportValue reads one value for an export: its bytes in full, up to 64 KiB;
// a masked value as its type and size.
func (e *engine) exportValue(k Key, name string) agentproto.RegValue {
	typ, size, err := k.ValueInfo(name)
	if err != nil {
		v := agentproto.EncodeRegValue(name, 0, nil, false, false, 0)
		v.NoData, v.Denied = true, errors.Is(err, ErrDenied)
		return v
	}
	if registryrules.IsMasked(name, typ) {
		v := agentproto.EncodeRegValue(name, typ, nil, true, false, 0)
		v.Size = size
		return v
	}
	if size > exportValueLimit {
		v := agentproto.EncodeRegValue(name, typ, nil, false, false, 0)
		v.Size, v.NoData = size, true
		return v
	}
	_, data, err := k.ReadValue(name)
	if err != nil {
		v := agentproto.EncodeRegValue(name, typ, nil, false, false, 0)
		v.Size, v.NoData, v.Denied = size, true, errors.Is(err, ErrDenied)
		return v
	}
	return agentproto.EncodeRegValue(name, typ, data, false, true, exportValueLimit)
}

// exportValueLimit is the most of one value an export carries.
const exportValueLimit = 64 << 10
