# Contribution
Any kind of contribution is encouraged, e.g., bug report, question answer, and submit pull-request.

Before taking actions, we highly recommend reading the documentation in [docs](docs).

## LF ID Application

All the tools require an Linux Foundation (LF) ID.

If you do not have an LF ID, can [apply one](https://identity.linuxfoundation.org) for free.

## Jira board usage

We are using [Jira](https://jira.hyperledger.org/secure/RapidBoard.jspa?rapidView=85) to track the project progress, and welcome to report bug issues or create to-do tasks there. Each item should try keeping simple and focused, hence easy to fix and review.

After login with your LF ID, you can see those task items may have 4 status:

* `To Do`: Available for picking.
* `In Progress`: Picked by someone (check the assignee) to work on.
* `In Review`: Related patchset has been submitted for review.
* `Done`: Patchset merged, the item is done.

In brief, if you want to contribute, create or find some `To Do` item, and assign it to yourself, then update its status to `In Progress`. After the item is fixed, remember to mark it as `In Review` and `Done` when the patch is submitted and merged.

## Questions and discussions

* [RocketChat](https://chat.hyperledger.org/channel/fabric-sdk-py): technical discussions and questions, login with your LF ID.

## Coding Style

We're following [pep8 style guide](https://www.python.org/dev/peps/pep-0008/) and [Google style](https://google.github.io/styleguide/pyguide.html), please see [coding style](docs/code_style.md)

## Code Commit Steps

The project employs [Gerrit](https://gerrit.hyperledger.org) as the code commit/review system. More details about Gerrit can be learned from the [Hyperledger Fabric Gerrit Doc](https://github.com/hyperledger/fabric/blob/master/docs/Gerrit/).

*Before committing code, please go to [Jira](https://jira.hyperledger.org/secure/RapidBoard.jspa?rapidView=85) to create a new task or check if there's related existing one, then assign yourself as the assignee. Notice each task will get a Jira number like [FAB-163](https://jira.hyperledger.org/browse/FABP-3082).


* Clone the project into your working directory with your LF ID (`LF ID`).

```sh
$ git clone ssh://LFID@gerrit.hyperledger.org:29418/fabric-sdk-py && scp -p -P 29418 LFID@gerrit.hyperledger.org:hooks/commit-msg fabric-sdk-py/.git/hooks/
```

(Optionally) Config your git name and email if not setup previously.

```sh
$ git config user.name "your name"
$ git config user.email "your email"
```

(Optionally) Setup git-review by inputting your LF ID. Notice this is only necessary once.
```sh
$ git review -s
```

* Assign yourself a `To Do` Jira task, mark it as `In progress`, then create a branch with the Jira task number off of your cloned repository, e.g., for FABP-164, it can be:

```sh
$ cd fabric-sdk-py
$ git pull
$ git checkout -b FABP-164
```

* After modifying the code, run `make check` to make sure all the checking is passed. Then Commit your code with `-s` to sign-off, and `-a` to automatically add changes (or run `git add .` to include all changes manually).

```sh
$ make check
  ...
  py27: commands succeeded
  py30: commands succeeded
  py35: commands succeeded
  flake8: commands succeeded
  congratulations :)

$ git commit -s -a
```

Example commit msg may look like:

```sh
[FABP-164] A short description of your change with no period at the end

You can add more details here in several paragraphs, but please keep each line
width less than 80 characters. A bug fix should include the issue number.

Fix https://jira.hyperledger.org/browse/FABP-164.

Change-Id: Ife0f1a3866a636991e36b0b5b25b8f58c9208b79
Signed-off-by: Your Name <committer@email.address>
```

* Submit your commit using `git review`.

```sh
$ git review
remote: Processing changes: new: 1, refs: 1, done
remote:
remote: New Changes:
remote:   http://gerrit.hyperledger.org/r/25966 [FABP-164] Enhance the contribution documentation
remote:
To ssh://gerrit.hyperledger.org:29418/fabric-sdk-py
 * [new branch]      HEAD -> refs/publish/master/FABP-164
```

Notice you will get a [gerrit item url](http://gerrit.hyperledger.org/r/7917), open and check the status.

After the ci checking passed, add [reviewers](https://wiki.hyperledger.org/projects/fabric-sdk-py#contributors) to the reviewer list and also post the gerrit item url at the [RocketChat channel](https://chat.hyperledger.org/channel/fabric-sdk-py). The patch will be merged into the `master` branch after passing the review, then mark the Jira item as `Done`.

* If you need to refine the patch further as the reviewers may suggest, you can change on the same branch, and commit the new code with `git commit -a --amend`, and then use the `git review` command again.

## Maintainers

The project’s [Maintainers](MAINTAINERS.md) are responsible for reviewing and merging all patches submitted for review and they guide the over-all technical direction of the project within the guidelines established by the Hyperledger Technical Steering Committee (TSC).


## Becoming a maintainer

The project’s maintainers will, from time-to-time, consider adding or removing a maintainer. An existing maintainer can submit a change set to the [Maintainers](MAINTAINERS.md) file. A nominated Contributor may become a Maintainer by a majority approval of the proposal by the existing Maintainers. Once approved, the change set is then merged and the individual is added to (or alternatively, removed from) the maintainers group. Maintainers may be removed by explicit resignation, for prolonged inactivity (3 or more months), or for some infraction of the code of conduct or by consistently demonstrating poor judgement. A maintainer removed for inactivity should be restored following a sustained resumption of contributions and reviews (a month or more) demonstrating a renewed commitment to the project.

## License <a name="license"></a>
Hyperledger Fabric-SDK-Py software uses the [Apache License Version 2.0](LICENSE) software license.

<a rel="license" href="http://creativecommons.org/licenses/by/4.0/"><img alt="Creative Commons License" style="border-width:0" src="https://i.creativecommons.org/l/by/4.0/88x31.png" /></a><br />This document is licensed under a <a rel="license" href="http://creativecommons.org/licenses/by/4.0/">Creative Commons Attribution 4.0 International License</a>.
