import { pool } from "./db.mjs";

class UserStore {
  async findByEmail(email) {
    const [rows] = await pool.query("SELECT * FROM user WHERE email = ?", [
      email,
    ]);
    return rows[0] || null;
  }

  async findByUsername(username) {
    const [rows] = await pool.query("SELECT * FROM user WHERE username = ?", [
      username,
    ]);
    return rows[0] || null;
  }

  async findById(id) {
    const [rows] = await pool.query("SELECT * FROM user WHERE id = ?", [id]);
    return rows[0] || null;
  }

  async create(user) {
    const [result] = await pool.query(
      "INSERT INTO user (username, email, password, is_active, profiling_form) VALUES (?, ?, ?, ?, ?)",
      [user.username, user.email, user.password, 1, 0]
    );
    const id = result.insertId;
    return { ...user, id, create_time: new Date() };
  }
}

export const userStore = new UserStore();
