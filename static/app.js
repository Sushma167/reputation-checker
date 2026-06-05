function toggleTheme(){

let html =
document.documentElement;

let current =
html.getAttribute("data-theme");

html.setAttribute(
"data-theme",
current==="dark" ? "light" : "dark"
);
}
