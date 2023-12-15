The reports should be self-sustaining so that we can send them in a single html file without dependencies.

This breaks common web standards as we want to include the CSS and the font etc in the HTML file.

To do this, we use bootstrap v5.2 and the following two bootstrap files from here https://getbootstrap.com/docs/5.2/getting-started/download/ :
1. Default bootstrap.min.css
2. Default bootstrap.bundle.min.js

Additionally we use the bootstrap icon file from here https://cdnjs.com/libraries/bootstrap-icons : 
3. CUSTOM boostrap-icons.css

# Icons
To use icons, we use the default bootstrap-icons.css from https://cdnjs.cloudflare.com/ajax/libs/bootstrap-icons/1.10.4/font/bootstrap-icons.css
But in the first few parameters, it uses:
```css
@font-face {
  font-display: block;
  font-family: "bootstrap-icons";
  src: url("./fonts/bootstrap-icons.woff2?1fa40e8900654d2863d011707b9fb6f2") format("woff2"),
url("./fonts/bootstrap-icons.woff?1fa40e8900654d2863d011707b9fb6f2") format("woff");
}
```

So we change the woff2 file into:

```css
@font-face {
  font-display: block;
  font-family: "bootstrap-icons";
  src:url(data:font/ttf;base64,<BASE64 ENCODED STRING FROM WOFF2.BAS64 FILE>) format("woff2");
}
```

The woff2 file is found here: https://cdnjs.cloudflare.com/ajax/libs/bootstrap-icons/1.10.4/font/fonts/bootstrap-icons.woff2
`base 64 -w 0 bootstrap-icons.woff2 > woff.base64` converts the file to a base64 string that can be pasted into the data above.

The final result is a customized, locally sourced bootstrap-icons.css.