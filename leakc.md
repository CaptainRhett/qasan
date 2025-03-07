
Leak-checking is a directed-graph traversal problem.  The graph has
two kinds of nodes:
- root-set nodes:
  - GP registers of all threads;
  - valid, aligned, pointer-sized data words in valid client memory,
    including stacks, but excluding words within client heap-allocated
    blocks (they are excluded so that later on we can differentiate
    between heap blocks that are indirectly leaked vs. directly leaked).
- heap-allocated blocks.  A block is a mempool chunk or a malloc chunk
  that doesn't contain a mempool chunk.  Nb: the terms "blocks" and
  "chunks" are used interchangeably below.
//
There are two kinds of edges:
- start-pointers, i.e. pointers to the start of a block;
- interior-pointers, i.e. pointers to the interior of a block.
//
We use "pointers" rather than "edges" below.
//
Root set nodes only point to blocks.  Blocks only point to blocks;
a block can point to itself.
//
The aim is to traverse the graph and determine the status of each block.
//
There are 9 distinct cases.  See memcheck/docs/mc-manual.xml for details.
Presenting all nine categories to the user is probably too much.
Currently we do this:
- definitely lost:  case 3
- indirectly lost:  case 4, 9
- possibly lost:    cases 5..8
- still reachable:  cases 1, 2

It's far from clear that this is the best possible categorisation;  it's
accreted over time without any central guiding principle.

/*------------------------------------------------------------*/
/*--- XXX: Thoughts for improvement.                       ---*/
/*------------------------------------------------------------*/

From the user's point of view:
- If they aren't using interior-pointers, they just have to fix the
  directly lost blocks, and the indirectly lost ones will be fixed as
  part of that.  Any possibly lost blocks will just be due to random
  pointer garbage and can be ignored.

- If they are using interior-pointers, the fact that they currently are not
  being told which ones might be directly lost vs. indirectly lost makes
  it hard to know where to begin.

All this makes me wonder if new option is warranted:
--follow-interior-pointers.  By default it would be off, the leak checker
wouldn't follow interior-pointers and there would only be 3 categories:
R, DL, IL.

If turned on, then it would show 7 categories (R, DL, IL, DR/DL, IR/IL,
IR/IL/DL, IL/DL).  That output is harder to understand but it's your own
damn fault for using interior-pointers...
//
----
//
Also, why are two blank lines printed between each loss record?
[bug 197930]
//
----
//
Also, --show-reachable is a bad name because it also turns on the showing
of indirectly leaked blocks(!)  It would be better named --show-all or
--show-all-heap-blocks, because that's the end result.
We now have the option --show-leak-kinds=... which allows to specify =all.
//
----
//
Also, the VALGRIND_LEAK_CHECK and VALGRIND_QUICK_LEAK_CHECK aren't great
names.  VALGRIND_FULL_LEAK_CHECK and VALGRIND_SUMMARY_LEAK_CHECK would be
better.
//
----
//
Also, VALGRIND_COUNT_LEAKS and VALGRIND_COUNT_LEAK_BLOCKS aren't great as
they combine direct leaks and indirect leaks into one.  New, more precise
ones (they'll need new names) would be good.  If more categories are
used, as per the --follow-interior-pointers option, they should be
updated accordingly.  And they should use a struct to return the values.
//
----
//
Also, for this case:
//
 (4)  p4      BBB ---> AAA

BBB is definitely directly lost.  AAA is definitely indirectly lost.
Here's the relevant loss records printed for a full check (each block is
16 bytes):

==20397== 16 bytes in 1 blocks are indirectly lost in loss record 9 of 15
==20397==    at 0x4C2694E: malloc (vg_replace_malloc.c:177)
==20397==    by 0x400521: mk (leak-cases.c:49)
==20397==    by 0x400578: main (leak-cases.c:72)

==20397== 32 (16 direct, 16 indirect) bytes in 1 blocks are definitely
lost in loss record 14 of 15
==20397==    at 0x4C2694E: malloc (vg_replace_malloc.c:177)
==20397==    by 0x400521: mk (leak-cases.c:49)
==20397==    by 0x400580: main (leak-cases.c:72)

The first one is fine -- it describes AAA.

The second one is for BBB.  It's correct in that 16 bytes in 1 block are
directly lost. It's also correct that 16 are indirectly lost as a result,
but it means that AAA is being counted twice in the loss records.  (It's
not, thankfully, counted twice in the summary counts).  Argh.

This would be less confusing for the second one:

==20397== 16 bytes in 1 blocks are definitely lost in loss record 14
of 15 (and 16 bytes in 1 block are indirectly lost as a result;  they
are mentioned elsewhere (if --show-reachable=yes or indirect is given
in --show-leak-kinds=... !))
==20397==    at 0x4C2694E: malloc (vg_replace_malloc.c:177)
==20397==    by 0x400521: mk (leak-cases.c:49)
==20397==    by 0x400580: main (leak-cases.c:72)

But ideally we'd present the loss record for the directly lost block and
then the resultant indirectly lost blocks and make it clear the
dependence.  Double argh.

/*------------------------------------------------------------*/
/*--- The actual algorithm.                                ---*/
/*------------------------------------------------------------*/

- Find all the blocks (a.k.a. chunks) to check.  Mempool chunks require
  some special treatment because they can be within malloc'd blocks.
- Scan every word in the root set (GP registers and valid
  non-heap memory words).
  - First, we skip if it doesn't point to valid memory.
  - Then, we see if it points to the start or interior of a block.  If
    so, we push the block onto the mark stack and mark it as having been
    reached.
- Then, we process the mark stack, repeating the scanning for each block;
  this can push more blocks onto the mark stack.  We repeat until the
  mark stack is empty.  Each block is marked as definitely or possibly
  reachable, depending on whether interior-pointers were required to
  reach it.
- At this point we know for every block if it's reachable or not.
- We then push each unreached block onto the mark stack, using the block
  number as the "clique" number.
- We process the mark stack again, this time grouping blocks into cliques
  in order to facilitate the directly/indirectly lost categorisation.
- We group blocks by their ExeContexts and categorisation, and print them
  if --leak-check=full.  We also print summary numbers.
//
A note on "cliques":
- A directly lost block is one with no pointers to it.  An indirectly
  lost block is one that is pointed to by a directly or indirectly lost
  block.
- Each directly lost block has zero or more indirectly lost blocks
  hanging off it.  All these blocks together form a "clique".  The
  directly lost block is called the "clique leader".  The clique number
  is the number (in lc_chunks[]) of the clique leader.
- Actually, a directly lost block may be pointed to if it's part of a
  cycle.  In that case, there may be more than one choice for the clique
  leader, and the choice is arbitrary.  Eg. if you have A-->B and B-->A
  either A or B could be the clique leader.
- Cliques cannot overlap, and will be truncated to avoid this.  Eg. if we
  have A-->C and B-->C, the two cliques will be {A,C} and {B}, or {A} and
  {B,C} (again the choice is arbitrary).  This is because we don't want
  to count a block as indirectly lost more than once.
//
A note on 'is_prior_definite': 
- This is a boolean used in various places that indicates if the chain
  up to the prior node (prior to the one being considered) is definite.
- In the clique == -1 case: 
  - if True it means that the prior node is a root-set node, or that the
    prior node is a block which is reachable from the root-set via
    start-pointers.
  - if False it means that the prior node is a block that is only
    reachable from the root-set via a path including at least one
    interior-pointer.
- In the clique != -1 case, currently it's always True because we treat
  start-pointers and interior-pointers the same for direct/indirect leak
  checking.  If we added a PossibleIndirectLeak state then this would
  change.