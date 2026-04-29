use turso::sync::Builder;

async fn open(path: &str) -> turso::Result<turso::sync::Database> {
    Builder::new_remote(path)
        .with_remote_url("http://127.0.0.1:8080")
        .build()
        .await
}

async fn read_rows(conn: &turso::Connection) -> turso::Result<Vec<(i64, String)>> {
    let mut stmt = conn.prepare("SELECT id, v FROM t ORDER BY id").await?;
    let mut rows = stmt.query(()).await?;
    let mut out = Vec::new();
    while let Some(row) = rows.next().await? {
        out.push((row.get(0)?, row.get(1)?));
    }
    Ok(out)
}

#[tokio::main]
async fn main() -> turso::Result<()> {
    let nonce = std::process::id();
    let a_path = format!("/tmp/turso-lww-a-{nonce}.db");
    let b_path = format!("/tmp/turso-lww-b-{nonce}.db");
    let c_path = format!("/tmp/turso-lww-c-{nonce}.db");

    let a = open(&a_path).await?;
    let a_conn = a.connect().await?;
    a_conn
        .execute(
            "CREATE TABLE IF NOT EXISTS t(id INTEGER PRIMARY KEY, v TEXT)",
            (),
        )
        .await?;
    a_conn
        .execute("INSERT INTO t VALUES (1, 'base')", ())
        .await?;
    a.push().await?;
    println!("after A base push: {:?}", read_rows(&a_conn).await?);

    let b = open(&b_path).await?;
    let b_conn = b.connect().await?;
    println!("B after bootstrap: {:?}", read_rows(&b_conn).await?);

    a_conn.execute("DELETE FROM t WHERE id = 1", ()).await?;
    a.push().await?;

    b_conn
        .execute("UPDATE t SET v = 'client-b' WHERE id = 1", ())
        .await?;
    b.push().await?;

    let c = open(&c_path).await?;
    let c_conn = c.connect().await?;
    let final_rows = read_rows(&c_conn).await?;
    println!("fresh client final rows: {final_rows:?}");

    if final_rows.is_empty() {
        println!("BUG REPRODUCED: later pushed UPDATE did not resurrect the deleted row");
    } else {
        println!("no repro: later pushed UPDATE won");
    }

    Ok(())
}
