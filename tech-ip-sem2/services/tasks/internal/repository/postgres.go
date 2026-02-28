package repository

import (
	"context"
	"database/sql"
	"fmt"

	_ "github.com/lib/pq"
	"github.com/sun1tar/MIREA-TIP-Practice-22/tech-ip-sem2/tasks/internal/models"
)

type PostgresTaskRepository struct {
	db *sql.DB
}

func NewPostgresTaskRepository(dsn string) (*PostgresTaskRepository, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}
	if err = db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}
	return &PostgresTaskRepository{db: db}, nil
}

func (r *PostgresTaskRepository) Close() error {
	return r.db.Close()
}

func (r *PostgresTaskRepository) Create(ctx context.Context, task *models.Task) error {
	query := `INSERT INTO tasks (id, title, description, done, created_at, updated_at) 
              VALUES ($1, $2, $3, $4, $5, $6)`
	_, err := r.db.ExecContext(ctx, query,
		task.ID, task.Title, task.Description, task.Done, task.CreatedAt, task.UpdatedAt)
	return err
}

func (r *PostgresTaskRepository) GetByID(ctx context.Context, id string) (*models.Task, error) {
	query := `SELECT id, title, description, done, created_at, updated_at FROM tasks WHERE id = $1`
	task := &models.Task{}
	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&task.ID, &task.Title, &task.Description, &task.Done, &task.CreatedAt, &task.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return task, nil
}

func (r *PostgresTaskRepository) List(ctx context.Context) ([]*models.Task, error) {
	query := `SELECT id, title, description, done, created_at, updated_at FROM tasks ORDER BY created_at DESC`
	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tasks []*models.Task
	for rows.Next() {
		task := &models.Task{}
		err := rows.Scan(&task.ID, &task.Title, &task.Description, &task.Done, &task.CreatedAt, &task.UpdatedAt)
		if err != nil {
			return nil, err
		}
		tasks = append(tasks, task)
	}
	return tasks, rows.Err()
}

func (r *PostgresTaskRepository) Update(ctx context.Context, task *models.Task) error {
	query := `UPDATE tasks SET title = $1, description = $2, done = $3, updated_at = NOW() WHERE id = $4`
	result, err := r.db.ExecContext(ctx, query, task.Title, task.Description, task.Done, task.ID)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (r *PostgresTaskRepository) Delete(ctx context.Context, id string) error {
	query := `DELETE FROM tasks WHERE id = $1`
	result, err := r.db.ExecContext(ctx, query, id)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// SearchByTitleUnsafe - УЯЗВИМАЯ ВЕРСИЯ для демонстрации SQL-инъекции
func (r *PostgresTaskRepository) SearchByTitleUnsafe(ctx context.Context, titleSubstring string) ([]*models.Task, error) {
	// ВНИМАНИЕ: ЭТОТ КОД УЯЗВИМ ДЛЯ SQL-ИНЪЕКЦИЙ! ТОЛЬКО ДЛЯ ДЕМОНСТРАЦИИ!
	query := fmt.Sprintf("SELECT id, title, description, done, created_at, updated_at FROM tasks WHERE title LIKE '%%%s%%'", titleSubstring)

	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tasks []*models.Task
	for rows.Next() {
		task := &models.Task{}
		err := rows.Scan(&task.ID, &task.Title, &task.Description, &task.Done, &task.CreatedAt, &task.UpdatedAt)
		if err != nil {
			return nil, err
		}
		tasks = append(tasks, task)
	}
	return tasks, rows.Err()
}

// SearchByTitle - БЕЗОПАСНАЯ ВЕРСИЯ с параметризованным запросом
func (r *PostgresTaskRepository) SearchByTitle(ctx context.Context, titleSubstring string) ([]*models.Task, error) {
	query := `SELECT id, title, description, done, created_at, updated_at FROM tasks WHERE title ILIKE $1`
	rows, err := r.db.QueryContext(ctx, query, "%"+titleSubstring+"%")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tasks []*models.Task
	for rows.Next() {
		task := &models.Task{}
		err := rows.Scan(&task.ID, &task.Title, &task.Description, &task.Done, &task.CreatedAt, &task.UpdatedAt)
		if err != nil {
			return nil, err
		}
		tasks = append(tasks, task)
	}
	return tasks, rows.Err()
}
