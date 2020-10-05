# SpecROP

This repository contains code used for the paper
*SpecROP: Speculative exploition of ROP chains*.
This work was published in the
23rd International Symposium on Research in Attacks, Intrusions and Defenses
(RAID 2020). The full paper is available
[here](http://hexhive.epfl.ch/publications/files/20RAID.pdf).

The folders are:

- contexts: This explores the contexts in which branch target poisoning
  is possible. This corresponds to Section 4.1 in the paper.
- chaining: This explores the number of gadgets which can be chained using
  BTB and RSB poisoning (Sections 4.1.1 and 4.1.2 respectively).
- poc: This is a laboratory proof-of-concept attack based on SMoTherSpectre
  and corresponds to Section 4.2 in the paper.
- openssl: This is a realistic attack on OpenSSL. This is described in
  Section 4.3 in the paper.

Please note that the results might change with processor microcode updates
and the software environment.
