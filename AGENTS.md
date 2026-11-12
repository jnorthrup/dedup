## Distributed 3way merge — D3M

D3M is the endorsed integration technique for distributed branch work. 


 1. git fetch

 2. git add . 

 3. git commit wip 

 4. git 3-way merge all unmerged branches in ascending order by time; UNBIASED.  UNBIASED means you do not keep existing, or keep new, you merge all, and retain all conflicts. 

 5. at the end you identify the intent of each conflict or blocks of conflicts for the intent and the fix.

 6. fix compilation and tests.  tests older than 30 days are no longer considered current tests.  better to delete them than fix them.  

 7. git push to origin master.  

 8. do not delete remote or local branches after merge or push,

For step 1, enumerate every remote with `git ls-remote --heads <remote>` and
fetch all branch heads explicitly with
`git fetch --no-prune <remote> 'refs/heads/*:refs/remotes/<remote>/*'`.
`git fetch --all` still obeys narrow fetch refspecs and can omit branches.
Freeze local and remote ref names, commit IDs and committer timestamps before
ordering; use commit ID then ref name to break equal-time ties. Verify every
frozen tip is an ancestor of the result before the ordinary master push.
Retain conflict index stages and base/left/right contents before resolving
intent; never use blanket side preference, force push or branch deletion.

Git requires a resolved index before the next sequential merge. Retain the
conflicted working file as well as stages 1/2/3, record each side's intent,
then resolve the minimum necessary to continue. Audit the complete merged
result at the end. Equivalent independently written fixes need one coherent
implementation with both histories retained; differing variable names are
not a reason to duplicate effects. Keep failed verification evidence and the
reason for its correction. Record tested commit/tree identities separately
from later documentation-only publication commits, and verify that tested
source and build inputs remain unchanged before relying on earlier checks.

A conflict-free merge and successful compilation do not establish runtime
acceptance. Execute the changed platform boundary against the actual packaged
artifact; preserve any failed candidate and its identity before rebuilding.
Keep measurement clocks and reporting thresholds explicit, and retain adverse
or overlapping results without turning them into an unsupported speedup claim.
Require complete expected evidence in the independent audit; a zero driver
exit does not establish that an awaited interaction or every check finished.
When a later experiment disproves an earlier diagnosis, correct the current
documentation and preserve the original evidence with its actual standing.
