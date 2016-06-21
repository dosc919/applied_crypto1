
function [p] = getNthConvergence(n, num)

a(1) = floor(num);
epsilon(1) = num - a(1);

for i = 2:n
  a(i) = floor(1 / epsilon(i - 1));
  epsilon(i) = 1 / epsilon(i - 1) - a(i);
end

p(1) = a(1);
p(2) = a(1) * a(2) + 1;

for i = 3:n
  p(i) = a(i) * p(i - 1) + p(i - 2);
end

endfunction
