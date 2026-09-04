# Reference-fix patch files

Each `.patch` is a diff between the vulnerable `master` and the fix for that task
(originally the `fix/<id>` branch). Each contains **only the fix itself**.

```bash
cat W1-01.patch                     # see the fix
git apply --check W1-01.patch       # verify it applies (no changes)
git apply W1-01.patch               # apply on master
git checkout -- .                   # revert
git apply ALL.patch                 # all fixes at once
```

The rationale ("why the fix is correct and what a naive fix would miss") is in
`secure-coding/week1.md`, `week2.md`, `week3.md`.
