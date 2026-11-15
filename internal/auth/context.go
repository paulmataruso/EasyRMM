package auth

import (
	"context"

	"github.com/paulmataruso/easyrm/pkg/models"
)

type contextKey string

const userContextKey contextKey = "user"
const sessionContextKey contextKey = "session"

func UserFromContext(ctx context.Context) *models.User {
	u, _ := ctx.Value(userContextKey).(*models.User)
	return u
}

func SessionFromContext(ctx context.Context) *models.Session {
	s, _ := ctx.Value(sessionContextKey).(*models.Session)
	return s
}

func SetUserContext(ctx context.Context, user *models.User) context.Context {
	return context.WithValue(ctx, userContextKey, user)
}

func SetSessionContext(ctx context.Context, sess *models.Session) context.Context {
	return context.WithValue(ctx, sessionContextKey, sess)
}
