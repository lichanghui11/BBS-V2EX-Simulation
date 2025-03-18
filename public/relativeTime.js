// relative time
function getRelativeTime(time) {
  const now = new Date();
  const past = new Date(time);
  const diffSeconds = Math.floor((now - past) / 1000);

  if (diffSeconds < 60) return "发布于：刚刚";
  if (diffSeconds < 3600)
    return `发布于：${Math.floor(diffSeconds / 60)}分钟前`;
  if (diffSeconds < 86400)
    return `发布于：${Math.floor(diffSeconds / 3600)}小时前`;
  if (diffSeconds < 2592000)
    return `发布于：${Math.floor(diffSeconds / 86400)}天前`;

  return "发布于：" + past.toLocaleString();
}

//页面加载后批量转换relative-time的时间
document.addEventListener("DOMContentLoaded", () => {
  const els = document.querySelectorAll(".relative-time");
  els.forEach((el) => {
    const utcTime = el.getAttribute("data-time");
    el.textContent = getRelativeTime(utcTime);
  });
});
