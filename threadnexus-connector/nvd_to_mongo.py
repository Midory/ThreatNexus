import os
import requests
import json
import logging
import psycopg2
import psycopg2.extras
from datetime import datetime, timedelta

# Configure logging
logging.basicConfig(level=logging.INFO)

def format_date(dt):
    """
    Format a datetime object into extended ISO‑8601 format: YYYY-MM-DDTHH:MM:SSZ
    """
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

def fetch_all_nvd_data(results_per_page=2000):
    """
    Fetch vulnerability data from the NVD REST API for the last 12 days,
    paging through the results if totalResults exceeds results_per_page.
    """
    now = datetime.utcnow()
    pub_end_date = format_date(now)
    pub_start_date = format_date(now - timedelta(days=90))
    vulnerabilities = []
    start_index = 0
    total_results = None

    while True:
        url = (
            f"https://services.nvd.nist.gov/rest/json/cves/2.0?"
            f"resultsPerPage={results_per_page}&startIndex={start_index}"
            f"&pubStartDate={pub_start_date}&pubEndDate={pub_end_date}&noRejected"
        )
        logging.info("Fetching data from URL: %s", url)
        try:
            response = requests.get(url)
            response.raise_for_status()
            data = response.json()
        except requests.RequestException as e:
            logging.error("Error fetching data from NVD API: %s", e)
            break

        # Set total_results from the first response
        if total_results is None:
            total_results = data.get("totalResults", 0)
            logging.info("Total results reported: %s", total_results)

        page_vulnerabilities = data.get("vulnerabilities", [])
        vulnerabilities.extend(page_vulnerabilities)
        logging.info("Fetched %d vulnerabilities (startIndex %d)", len(page_vulnerabilities), start_index)

        start_index += results_per_page
        if start_index >= total_results:
            break

    return vulnerabilities

def init_db(conn):
    """
    Create the vulnerabilities table if it doesn't exist.
    The table stores the CVE ID and the full vulnerability data as JSON.
    """
    create_table_query = """
    CREATE TABLE IF NOT EXISTS vulnerabilities (
        id SERIAL PRIMARY KEY,
        cve_id VARCHAR(50) UNIQUE,
        data JSONB
    );
    """
    with conn.cursor() as cur:
        cur.execute(create_table_query)
        conn.commit()
    logging.info("Database initialized and table created if it didn't exist.")

def store_vulnerabilities(conn, vulnerabilities):
    """
    Store vulnerabilities in the PostgreSQL database using an upsert (ON CONFLICT).
    """
    insert_query = """
    INSERT INTO vulnerabilities (cve_id, data)
    VALUES (%s, %s)
    ON CONFLICT (cve_id) DO UPDATE
      SET data = EXCLUDED.data;
    """
    
    with conn.cursor() as cur:
        for vuln in vulnerabilities:
            cve_info = vuln.get("cve", {})
            cve_id = cve_info.get("id")
            if cve_id:
                try:
                    cur.execute(insert_query, (cve_id, json.dumps(vuln)))
                    logging.info("Inserted/Updated vulnerability: %s", cve_id)
                except Exception as e:
                    logging.error("Error inserting vulnerability %s: %s", cve_id, e)
            else:
                logging.warning("Vulnerability without valid CVE ID encountered.")
        conn.commit()
    logging.info("All vulnerabilities processed and stored.")

def main():
    # PostgreSQL connection settings from environment variables.
    pg_host = os.environ.get("PG_HOST", "localhost")
    pg_port = os.environ.get("PG_PORT", "5432")
    pg_db = os.environ.get("PG_DB", "nvd_database")
    pg_user = os.environ.get("PG_USER", "postgres")
    pg_password = os.environ.get("PG_PASSWORD", "example")
    
    conn_string = f"host={pg_host} port={pg_port} dbname={pg_db} user={pg_user} password={pg_password}"
    logging.info("Connecting to PostgreSQL using: %s", conn_string)
    
    try:
        conn = psycopg2.connect(conn_string)
    except Exception as e:
        logging.error("Could not connect to PostgreSQL: %s", e)
        return

    # Initialize the database (create table if it doesn't exist)
    init_db(conn)
    
    # Fetch all vulnerabilities from the NVD API (paginated if necessary)
    vulnerabilities = fetch_all_nvd_data(results_per_page=2000)
    if not vulnerabilities:
        logging.error("No vulnerabilities retrieved; exiting.")
        conn.close()
        return

    # Store the vulnerabilities into PostgreSQL
    store_vulnerabilities(conn, vulnerabilities)
    
    conn.close()
    logging.info("Data storage complete and connection closed.")

if __name__ == "__main__":
    main()
