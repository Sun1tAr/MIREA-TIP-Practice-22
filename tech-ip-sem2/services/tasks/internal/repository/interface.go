package repository

import (
	"context"
	"github.com/sun1tar/MIREA-TIP-Practice-22/tech-ip-sem2/tasks/internal/models"
)

type TaskRepository interface {
	Create(ctx context.Context, task *models.Task) error
	GetByID(ctx context.Context, id string) (*models.Task, error)
	List(ctx context.Context) ([]*models.Task, error)
	Update(ctx context.Context, task *models.Task) error
	Delete(ctx context.Context, id string) error
	SearchByTitle(ctx context.Context, titleSubstring string) ([]*models.Task, error)
}
