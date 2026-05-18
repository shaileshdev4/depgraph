/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  theme: {
    extend: {
      colors: {
        canvas: "#0a0a0a",
        card: "#111111",
        border: "#222222",
      },
    },
  },
  plugins: [],
};
