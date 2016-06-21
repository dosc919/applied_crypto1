close all;
clear all;

#Enter number to factor here
n = 0x347b702f; #0x347b702f, 9073, 1829, 84923

base = primes(2 ^ (sqrt(log(n) * log(log(n)))));
#base = [-1 base];

a_min = floor(sqrt(n));
a_max = n;

p = 1;

while((p == 1) || (p == n))
  f = zeros(2 * length(base) + 1, length(base));
  tmp = 0;
  ind = 1;
  for i = floor(sqrt(n)):floor(sqrt(n)) + 2 * length(base)
    while(all(not(f(ind))) && (tmp != 1))
      r = (a_max - a_min) * rand(1, 1) + a_min;
      a(ind) = round(r);
      b(ind) = mod(a(ind) ^ 2, n);
      #if(b(ind) > n/2)
      #  f(ind, 1) = 1;
      #  b(ind) = b(ind) - n;
      #end
      tmp = b(ind);
      for j = 2:length(base);
        count = 0;
        while(not(mod(tmp, base(j))))
          count = count + 1;
          tmp = tmp / base(j);
        end
        f(ind ,j) = count;
      end
    end
    tmp = 0;
    ind = ind + 1;
  end

  p = 1;
  for i = 1:length(a)
    sum_bases = f(i,:);
    sum_b = b(i);
    sum_a = a(i);
    for j = i + 1:length(a)
      if(all(not(mod(sum_bases(:),2))))
        p = gcd(sum_a - sqrt(sum_b), n);
        if((p != 1) && (p != n))
          break;
        end
      end
      sum_b = sum_b * b(j);
      sum_a = mod(sum_a * a(j), n);
      sum_bases = sum_bases + f(j,:);
    end
    if((p != 1) && (p != n))
      break;
    end
  end
end

if((p != 1) && (p != n))
  p
  q = n/p
else
  disp("nothing found :(");
end