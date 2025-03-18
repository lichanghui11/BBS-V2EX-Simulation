/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    // 这里配置要扫描的文件路径，确保包含 Pug 文件的路径
    "./templates/*.pug",
  ],
  theme: {
    extend: {},
  },
  plugins: [],
};
