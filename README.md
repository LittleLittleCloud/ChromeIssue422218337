## How to reproduce
To reproduce the chrome/edge browsers get closed issue, do the following:
- on Windows, update chrome/edge to the latest version
- open multiple chrome/edge browsers
- run the following code:

```bash
# this will list all toplevel windows
dotnet run list
```
- from the output above, select any chrome/edge window and copy its Handle (e.g. 0x12345678)
- run the following code, replacing `0x12345678` with the copied handle:

```bash
dotnet run close 0x12345678
```

- You will see that all browsers are closed instead of the chosen one.

## Possible Workaround
using `PostMessage` instead of `SendMessage` to close selected windows
