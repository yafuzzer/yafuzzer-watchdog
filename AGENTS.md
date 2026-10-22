# Repository Contribution Guidelines

These instructions apply to the entire repository. Follow them when making changes here.

## Branches and releases

- Keep `main` and `develop` as the two long-lived branches.
- `main` contains stable, release-ready code. Do not commit directly to `main`.
- `develop` is the integration branch and may contain work that is not yet stable.
- Promote reviewed changes from `develop` to `main` through a pull request.
- Create a GitHub release tag for each release merged into `main`.

## Working branches

- Create a short-lived branch from `develop` for every substantial change, especially changes that span multiple files.
- Name the branch `<action>/<target>`. Use an action such as `feature`, `fix`, or `refactor`; make the target a concise description, such as a feature name, `docs`, or `ci`.
- Small, atomic changes may be made directly on `develop`. If you are unsure whether a change is substantial, use a working branch.
- When the work is ready, open a pull request from the working branch to `develop` and request review. After the pull request is approved and merged, delete the working branch.

## Commit messages

- Write a short, descriptive commit subject that starts with a change type, such as `new`, `fix`, `remove`, or `refactor`.
- Mention the affected part of the codebase in the subject when it makes the change easier to identify (for example, a package, file, or component).
- Add a commit body only when more context is needed to explain the change.

## Working in the repository

- Before editing, inspect the current branch, working tree, and relevant files.
- Preserve unrelated changes already present in the working tree. Do not discard or overwrite them.
- Keep changes focused on the requested task and follow existing project conventions.
