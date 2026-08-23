/* 学员端页面守卫：无有效访问令牌时踢回邀请码入口页 */
(function () {
  // 入口页（有邀请码表单）不执行守卫
  if (document.getElementById("entry-form")) return;

  var token = sessionStorage.getItem("nav_token");
  if (!token) {
    location.replace("./安装导航-进入页原型.html");
    return;
  }

  fetch("/api/check", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ token: token }),
  })
    .then(function (r) { return r.json(); })
    .then(function (data) {
      if (!data || !data.ok) {
        sessionStorage.removeItem("nav_token");
        location.replace("./安装导航-进入页原型.html");
      }
    })
    .catch(function () { /* 网络异常时放行，避免误伤 */ });
})();
