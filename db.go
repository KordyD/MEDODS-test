package main

import (
	"database/sql"
	"fmt"
	"golang.org/x/crypto/bcrypt"
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
	connection := fmt.Sprintf("postgres://%s:%s@localhost:5432/%s?sslmode=disable", dbUsername, dbPassword, dbName)
	db, err := sql.Open("postgres", connection)
	if err != nil {
		log.Fatalf("Error in connection: %s", err)
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

func (p *PostgresDB) ValidateRefreshToken(userId string, providedToken string, ipAddress string) error {
	var storedToken string
	query := `SELECT token_hash FROM tokens WHERE user_id = $1`
	rows, err := p.db.Query(query, userId)
	if err != nil {
		return err
	}
	defer rows.Close()

	if !rows.Next() {
		return fmt.Errorf("no refresh token found for user")
	}

	err = rows.Scan(&storedToken)
	if err != nil {
		return err
	}

	err = bcrypt.CompareHashAndPassword([]byte(storedToken), []byte(providedToken))
	if err != nil {
		return err
	}

	return nil
}
