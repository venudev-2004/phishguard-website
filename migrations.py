from sqlalchemy import text, inspect
from models import db, User, ScanResult, ApiCache

def migrate_database(app):
    """Entry point for database migrations."""
    upgrade_database_schema(app)

def upgrade_database_schema(app):
    """
    Check and fix database schema by adding missing columns to all tables.
    Runs on application startup.
    """
    with app.app_context():
        # Map of table names to their expected columns and types
        # format: { 'table_name': [('col_name', 'SQL_TYPE', 'DEFAULT_VAL'), ...] }
        schema_definition = {
            'users': [
                ('is_admin', 'BOOLEAN DEFAULT 0 NOT NULL', '0')
            ],
            'scan_results': [
                ('google_safe_status', 'BOOLEAN', 'NULL'),
                ('virustotal_positives', 'INTEGER', 'NULL'),
                ('virustotal_total', 'INTEGER', 'NULL'),
                ('virustotal_confidence', 'FLOAT', 'NULL'),
                ('virustotal_permalink', 'VARCHAR(512)', 'NULL'),
                ('whois_creation_date', 'DATETIME', 'NULL'),
                ('whois_age_days', 'INTEGER', 'NULL'),
                ('whois_registrar', 'VARCHAR(255)', 'NULL'),
                ('ssl_valid', 'BOOLEAN', 'NULL'),
                ('ssl_issuer', 'VARCHAR(255)', 'NULL'),
                ('ssl_expiry_date', 'DATETIME', 'NULL'),
                ('ssl_days_until_expiry', 'INTEGER', 'NULL'),
                ('ssl_is_self_signed', 'BOOLEAN', 'NULL'),
                ('urlscan_uuid', 'VARCHAR(64)', 'NULL'),
                ('urlscan_report_url', 'VARCHAR(512)', 'NULL'),
                ('urlscan_screenshot_url', 'VARCHAR(512)', 'NULL'),
                ('urlscan_malicious', 'BOOLEAN', 'NULL'),
                ('composite_risk_score', 'FLOAT', 'NULL'),
                ('risk_label', 'VARCHAR(32)', 'NULL'),
            ]
        }

        try:
            inspector = inspect(db.engine)
            
            for table_name, expected_columns in schema_definition.items():
                if not inspector.has_table(table_name):
                    app.logger.warning(f"Table {table_name} not found, skipping migration.")
                    continue

                existing_columns = [c['name'] for c in inspector.get_columns(table_name)]
                
                for col_name, col_type, default_val in expected_columns:
                    if col_name not in existing_columns:
                        app.logger.info(f"Adding missing column '{col_name}' to table '{table_name}'...")
                        
                        try:
                            with db.engine.connect() as conn:
                                # SQLite ALTER TABLE ADD COLUMN syntax
                                conn.execute(text(f"ALTER TABLE {table_name} ADD COLUMN {col_name} {col_type}"))
                                
                                # If a specific update is needed after adding
                                if default_val != 'NULL':
                                    conn.execute(text(f"UPDATE {table_name} SET {col_name} = {default_val}"))
                                
                                conn.commit()
                            app.logger.info(f"Successfully added column '{col_name}' to '{table_name}'.")
                        except Exception as e:
                            app.logger.error(f"Failed to add column '{col_name}' to '{table_name}': {str(e)}")
                            
        except Exception as e:
            app.logger.error(f"Database schema upgrade failed: {str(e)}")
