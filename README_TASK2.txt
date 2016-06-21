###########################################
Task 2-A: Wiener's Attack on RSA:

Implemented using SAGE (sage.tugraz.at). The first part (a) can 
be found in the 'nth-convergent' Sage-Worksheet. The second
part (b) can be found in 'wiener-attack' Sage-Worksheet located
in the folder task2a.

###########################################
Task 2-B: Discrete Logarithms with Pollard-rho:

Implemented using SAGE (sage.tugraz.at). This time, the whole
task is implemented in one worksheet, found in the folder task2b.
The 32 bit attack works fine, with a runtime of a few seconds.
The 64 bit attack works a bit different. There we used the Multistage
Method from the given paper to reduce some calculation time.
With the normal algorithm sage cuts off the calculation before
it is finished. In the multistage method the prime -1 gets factored
and reduced by the greatest prime factor. Then we get a new y and
g which are labelled Y and G to distinguish them from the normal ones.
With this Y and G you can run the normal alogrithm up to the gcd
part, where the original values are needed. This multistage method
speeds up the whole calculation so that it is done in ~2 minutes.

###########################################
Task 2-C: 

Implementation in matlab/octave
execute task2c_a.m script to factor with dixons factoring method.
The number to factor can be entered in the beginning of the script.

the function getNthConvergence(n, number) returns the first n steps
of the convertions of the number (numerator only)

task2c_c.m script contains the continued fraction factoring method.
It doesn't work for all numbers including the number from the
assignment sheet.
Factoring the 32-bit number from the assignment document works
fine with task2c_a.m though (in reasonable time: 5~10min).
