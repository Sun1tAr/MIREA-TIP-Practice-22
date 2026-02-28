package service

import (
	"context"
	"database/sql"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/sun1tar/MIREA-TIP-Practice-22/tech-ip-sem2/tasks/internal/models"
	"github.com/sun1tar/MIREA-TIP-Practice-22/tech-ip-sem2/tasks/internal/repository"
)

// sanitizeInput - простая защита от XSS (замена опасных символов)
func sanitizeInput(input string) string {
	replacer := strings.NewReplacer(
		"<", "&lt;",
		">", "&gt;",
		"&", "&amp;",
		"\"", "&quot;",
		"'", "&#39;",
	)
	return replacer.Replace(input)
}

type TaskService struct {
	repo repository.TaskRepository
}

func NewTaskService(repo repository.TaskRepository) *TaskService {
	return &TaskService{
		repo: repo,
	}
}

func (s *TaskService) Create(ctx context.Context, title, description, dueDate string) (*models.Task, error) {
	// Санитизация входных данных
	title = sanitizeInput(title)
	description = sanitizeInput(description)

	task := &models.Task{
		ID:          "t_" + uuid.New().String(),
		Title:       title,
		Description: description,
		DueDate:     dueDate,
		Done:        false,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	if err := s.repo.Create(ctx, task); err != nil {
		return nil, err
	}
	return task, nil
}

func (s *TaskService) GetByID(ctx context.Context, id string) (*models.Task, error) {
	task, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if task == nil {
		return nil, sql.ErrNoRows
	}
	return task, nil
}

func (s *TaskService) List(ctx context.Context) ([]*models.Task, error) {
	return s.repo.List(ctx)
}

func (s *TaskService) Update(ctx context.Context, id string, title, description, dueDate *string, done *bool) (*models.Task, error) {
	// Сначала получаем существующую задачу
	existing, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if existing == nil {
		return nil, sql.ErrNoRows
	}

	// Обновляем поля с санитизацией
	if title != nil {
		existing.Title = sanitizeInput(*title)
	}
	if description != nil {
		existing.Description = sanitizeInput(*description)
	}
	if dueDate != nil {
		existing.DueDate = *dueDate // дату не санитируем
	}
	if done != nil {
		existing.Done = *done
	}
	existing.UpdatedAt = time.Now()

	// Сохраняем
	if err := s.repo.Update(ctx, existing); err != nil {
		return nil, err
	}
	return existing, nil
}

func (s *TaskService) Delete(ctx context.Context, id string) error {
	return s.repo.Delete(ctx, id)
}

func (s *TaskService) SearchByTitle(ctx context.Context, query string, unsafe bool) ([]*models.Task, error) {
	if unsafe {
		// В реальном коде так делать нельзя! Только для демонстрации SQL-инъекции
		if postgresRepo, ok := s.repo.(*repository.PostgresTaskRepository); ok {
			return postgresRepo.SearchByTitleUnsafe(ctx, query)
		}
	}
	// Санитизация поискового запроса (хотя параметризованный запрос уже безопасен)
	query = sanitizeInput(query)
	return s.repo.SearchByTitle(ctx, query)
}
