package egoutil

import (
	"context"
	"fmt"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"golang.org/x/oauth2/google"
	secretmanagerpb "google.golang.org/genproto/googleapis/cloud/secretmanager/v1"
)

func GetProjectID(ctx context.Context) (string, error) {
	credentials, err := google.FindDefaultCredentials(ctx)
	if err != nil {
		return "", err
	}
	return credentials.ProjectID, nil
}

type GCPSecrets struct {
	client *secretmanager.Client
	id     string
}

func NewGCPSecrets(ctx context.Context) (*GCPSecrets, error) {
	c, err := secretmanager.NewClient(ctx)
	if err != nil {
		return nil, err
	}

	id, err := GetProjectID(ctx)
	if err != nil {
		return nil, err
	}

	return &GCPSecrets{c, id}, nil
}

func (g *GCPSecrets) GetSecretOrPanic(ctx context.Context, name string) string {
	v, err := g.GetSecret(ctx, name)
	if err != nil {
		panic(err)
	}
	return v
}

func (g *GCPSecrets) GetSecret(ctx context.Context, name string) (string, error) {
	accessRequest := &secretmanagerpb.AccessSecretVersionRequest{
		Name: fmt.Sprintf("projects/%s/secrets/%s/versions/latest", g.id, name),
	}
	result, err := g.client.AccessSecretVersion(ctx, accessRequest)
	if err != nil {
		return "", fmt.Errorf("failed to access secret version: %w", err)
	}
	return string(result.Payload.Data), nil
}
