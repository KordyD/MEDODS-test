package storage

import (
	"database/sql"
	"fmt"
	"log"
	"os"
)

type PostgresDB struct {
	db *sql.DB
}

func NewPostgres() *PostgresDB {
	dbUsername := os.Getenv("DB_USERNAME")
	dbPassword := os.Getenv("DB_PASSWORD")
	dbName := os.Getenv("DB_NAME")
	dbHost := os.Getenv("DB_HOST")
	log.Println(dbUsername, dbPassword, dbName)
	connection := fmt.Sprintf("postgres://%s:%s@%s:5432/%s?sslmode=disable", dbUsername, dbPassword, dbHost, dbName)
	db, err := sql.Open("postgres", connection)
	if err != nil {
		log.Fatalf("Error in connection: %s", err)
	}
	query := `
		CREATE TABLE IF NOT EXISTS tokens (
    		user_id uuid PRIMARY KEY,
    		token_hash VARCHAR(255),
    		ip VARCHAR(255)
		)
	`
	_, err = db.Exec(query)
	if err != nil {
		log.Fatalf("Error creating table: %s", err)
	}
	return &PostgresDB{db: db}
}

func (p *PostgresDB) SaveRefreshToken(userId string, tokenHash string, ip string) (int64, error) {
	tx, err := p.db.Begin()
	if err != nil {
		return 0, err
	}
	query := `
		INSERT INTO tokens (user_id, token_hash, ip) VALUES ($1, $2, $3) 
		ON CONFLICT (user_id) DO UPDATE
		    SET token_hash = excluded.token_hash,
		        ip = excluded.ip
	`
	res, err := tx.Exec(query, userId, tokenHash, ip)
	if err != nil {
		tx.Rollback()
		return 0, err
	}
	rowsAffected, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}
	err = tx.Commit()
	if err != nil {
		return 0, err
	}
	return rowsAffected, nil
}

func (p *PostgresDB) GetRefreshToken(userId string) (string, error) {
	var storedToken string
	query := `SELECT token_hash FROM tokens WHERE user_id = $1`
	rows, err := p.db.Query(query, userId)
	if err != nil {
		return "", err
	}
	defer rows.Close()

	if !rows.Next() {
		return "", fmt.Errorf("no refresh token found for user")
	}

	err = rows.Scan(&storedToken)
	if err != nil {
		return "", err
	}

	return storedToken, nil
}
