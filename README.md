# Cookieless Session Scanner
A BurpSuite plugin to help detect ASP.NET cookieless sessions which can often lead to XSS as described [here](https://blog.isec.pl/all-is-xss-that-comes-to-the-net/). This plugin adds an active scanner check which test for ASP.NET cookieless sessions, and also creates a custom scanner insertion point when a cookieless sessions is present in the path of a request.
