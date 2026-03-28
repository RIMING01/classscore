export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    let body = {};
    if (request.method === "POST") {
      body = await request.json().catch(() => ({}));
    }

    // =========================
    // /login - 登录接口
    // =========================
    if (path === "/login") {
      const { username, password } = body;
      if (!username || !password)
        return new Response("缺少用户名或密码", { status: 400 });

      const user = await env.D1.prepare(
        "SELECT id, username, role, password FROM users WHERE username=?"
      )
        .bind(username)
        .first();

      if (!user) return new Response("用户不存在", { status: 404 });
      if (user.password !== password) return new Response("密码错误", { status: 403 });

      // 生成 token（简单随机字符串）
      const token = crypto.randomUUID();

      // 保存 token 到 sessions 表
      await env.D1.prepare(
        "INSERT INTO sessions (token, user_id) VALUES (?, ?) ON CONFLICT(token) DO UPDATE SET user_id=?"
      )
        .bind(token, user.id, user.id)
        .run();

      return new Response(JSON.stringify({ username: user.username, role: user.role, token }));
    }

    // =========================
    // token 验证函数
    // =========================
    async function verifyToken(token) {
      if (!token) return null;
      const session = await env.D1.prepare(
        "SELECT u.id, u.username, u.role FROM users u JOIN sessions s ON u.id=s.user_id WHERE s.token=?"
      )
        .bind(token)
        .first();
      return session || null;
    }

    // 获取 token
    const token = request.headers.get("Authorization")?.replace("Bearer ", "");
    const authUser = await verifyToken(token);

    if (!authUser) return new Response("未登录或 token 无效", { status: 401 });

    // =========================
    // /score - 查询自己的分数
    // =========================
    if (path === "/score") {
      const user = await env.D1.prepare(
        "SELECT score FROM users WHERE id=?"
      )
        .bind(authUser.id)
        .first();
      return new Response(JSON.stringify({ username: authUser.username, score: user.score }));
    }

    // =========================
    // /modify - 教师加分
    // =========================
    if (path === "/modify") {
      const { target, delta } = body;
      if (!target || typeof delta !== "number")
        return new Response("参数错误", { status: 400 });

      if (authUser.role !== "teacher")
        return new Response("操作失败：非教师无权限", { status: 403 });

      // 获取目标用户分数
      const targetUser = await env.D1.prepare(
        "SELECT id, score FROM users WHERE username=?"
      )
        .bind(target)
        .first();

      if (!targetUser) return new Response("目标用户不存在", { status: 404 });

      const newScore = targetUser.score + delta;

      await env.D1.prepare(
        "UPDATE users SET score=? WHERE id=?"
      )
        .bind(newScore, targetUser.id)
        .run();

      return new Response(JSON.stringify({ target, newScore }));
    }

    return new Response("接口不存在", { status: 404 });
  }
};
