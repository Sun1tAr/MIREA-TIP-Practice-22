CREATE TABLE IF NOT EXISTS tasks (
                                     id TEXT PRIMARY KEY,
                                     title TEXT NOT NULL,
                                     description TEXT,
                                     done BOOLEAN NOT NULL DEFAULT FALSE,
                                     created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
    );

-- Индекс для поиска по title
CREATE INDEX IF NOT EXISTS idx_tasks_title ON tasks(title);