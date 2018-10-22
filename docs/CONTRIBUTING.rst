.. role:: bolditalic
    :class: bolditalic

=======================
Contributing guidelines
=======================

We thank you in advance |thumbup| |tada| for taking the time to
contribute, whether with *code* or with *ideas*, to the Local EGA cryptor
project.

------------------------
AGILE project management
------------------------

We use *Zenhub*, the Agile project management within Github.

You should first `install it`_ if you want to contribute or just follow the project progress.
You can also use the `Zenhub app`_ if you wish.

In short, the `AGILE method`_ helps developers organize themselves:

* They decide about the tasks (not the managers)
* Main Tasks should be divided into smaller manageable ones. The big
  tasks are called *Epics*.
* We have a given period (called Sprint) to work on a chosen
  task. Here, a Sprint spans across 2 weeks.
* We review the work done at the end of the Sprint, closing issues or
  pushing them into the next Sprint. Ideally, they are sub-divided in
  case they encounter obstacles.
* We have a short meeting every weekday at 9:30 AM. We call it a
  *standup* and we use it to keep everyone on point, and identify
  quickly blockers. It's not a lengthy discussion. We ask:

  - What did you get done yesterday (or last week, last month, etc.)?
  - What are you working on now?
  - What isn’t going well, and on what could you use help?

---------
Procedure
---------

1. Create an issue on Github, and talk to the team members on the NBIS
   local-ega Slack channel. You can alternatively pick one already
   created.

.. note::
   Contact `Jonas Hagberg`_ to request access if you are not part of that channel already.


2. Assign yourself to that issue.

#. Discussions on how to proceed about that issue take place in the
   comment section on that issue, beforehand.

   The keyword here is *beforehand*. It is usually a good idea to talk
   about it first. Somebody might have already some pieces in place,
   we avoid unnecessary work duplication and a waste of time and
   effort.

#. Work on it (on a fork, or on a separate branch) as you wish. That's
   what ``git`` is good for. This GitHub repository follows
   the `coding guidelines from NBIS`_.

   Name your branch as you wish and prefix the name with:

   * ``feature/`` if it is a code feature
   * ``hotfix/`` if you are fixing an urgent bug

   Use comments in your code, choose variable and function names that
   clearly show what you intend to implement.

   Use `git rebase -i`_ in
   order to rewrite your history, and have meaningful commits.  That
   way, we avoid the 'Typo', 'Work In Progress (WIP)', or
   'Oops...forgot this or that' commits.

   Limit the first line of your git commits to 72 characters or less.


#. Create a Pull Request (PR), so that your code is reviewed by the
   admins on this repository.

   That PR should be connected to the issue you are working on.
   Moreover, the PR:

   - should use ``Estimate=1``,
   - should be connected to:

     * an ``Epic``,
     * a ``Milestone`` and
     * a ``User story``
     * ... or several.

   N.B: Pull requests are done to the ``dev`` branch. PRs to ``master`` are rejected.

#. Selecting a review goes as follows: Pick one *main* reviewer.  It
   is usually one that you had discussions with, and is somehow
   connected to that issue. If this is not the case, pick several reviewers.

   Note that, in turn, the main reviewer might ask another reviewer
   for help. The approval of all reviewers is compulsory in order to
   merge the PR. Moreover, the main reviewer is the one merging the
   PR, not you.

   Find more information on the `NBIS reviewing guidelines`_.


#. It is possible that your PR requires changes (because it creates
   conflicts, doesn't pass the integrated tests or because some parts
   should be rewritten in a cleaner manner, or because it does not
   follow the standards, or you're requesting the wrong branch to pull
   your code, etc...) In that case, a reviewer will request changes
   and describe them in the comment section of the PR.

   You then update your branch with new commits. We will see the PR
   changes faster if you ping the reviewer in the slack channel.

   Note that the comments *in the PR* are not used to discuss the
   *how* and *why* of that issue. These discussions are not about the
   issue itself but about *a solution* to that issue.

   Recall that discussions about the issue are good and prevent
   duplicated or wasted efforts, but they take place in the comment
   section of the related issue (see point 4), not in the PR.

   Essentially, we don't want to open discussions when the work is
   done, and there is no recourse, such that it's either accept or
   reject. We think we can do better than that, and introduce a finer
   grained acceptance, by involving *beforehand* discussions so that
   everyone is on point.



-------------------
Did you find a bug?
-------------------

* Ensure that the bug was not already reported by `searching under Issues`_.

* Do :bolditalic:`not` file it as a plain GitHub issue (we use the
  issue system for our internal tasks (see Zenhub)).  If you're unable
  to find an (open) issue addressing the problem, `open a new one`_.
  Be sure to prefix the issue title with **[BUG]** and to include:

  - a *clear* description,
  - as much relevant information as possible, and
  - a *code sample* or an (executable) *test case* demonstrating the expected behaviour that is not occurring.

* If possible, use the following `template to report a bug`_.

.. todo:: Make that template


----

| Thanks again,
| /NBIS System Developers

.. _Zenhub: https://www.zenhub.com
.. _install it: https://www.zenhub.com/extension
.. _Zenhub app: https://app.zenhub.com
.. _AGILE method: https://www.zenhub.com/blog/how-to-use-github-agile-project-management
.. _Jonas Hagberg: https://nbis.se/about/staff/jonas-hagberg/
.. _coding guidelines from NBIS: https://github.com/NBISweden/development-guidelines
.. _git rebase -i: https://git-scm.com/book/en/v2/Git-Tools-Rewriting-History
.. _NBIS reviewing guidelines: https://github.com/NBISweden/development-guidelines#how-we-do-code-reviews
.. _searching under Issues: https://github.com/NBISweden/LocalEGA-cryptor/issues?utf8=%E2%9C%93&q=is%3Aissue%20label%3Abug%20%5BBUG%5D%20in%3Atitle
.. _open a new one: https://github.com/NBISweden/LocalEGA-cryptor/issues/new?title=%5BBUG%5D
.. _template to report a bug: todo
.. |tada| unicode:: U+1f389
.. |thumbup| unicode:: U+1f44d
