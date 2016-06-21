close all;
clear all;

#Enter number to factor here
n = 84923; #9073, 1829, 84923

base = primes(exp(sqrt(log(n) * log(log(n)))));
base = [-1 base];

f = zeros(2 * length(base) + 1, length(base));
tmp = 0;
ind = 1;

p_i = getNthConvergence(length(base), sqrt(n));
for i = floor(sqrt(n)):floor(sqrt(n)) + round(length(base) / 2) - 1
  a(ind) = p_i(ind);
  b(ind) = mod(a(ind) ^ 2, n);
  if(b(ind) > n/2)
    f(ind, 1) = 1;
    b(ind) = b(ind) - n;
  end
  tmp = abs(b(ind));
  for j = 2:length(base);
    count = 0;
    while(not(mod(tmp, base(j))))
      count = count + 1;
      tmp = tmp / base(j);
    end
    f(ind, j) = count;
  end
  if(tmp != 1)
    f(ind, :) = zeros(1, length(base));
  end
  ind = ind + 1;
end

ind = 1;
for i = 1:length(f)
  if(not(all(not(f(i,:)))))
    f_smooth(ind, :) = f(i, :);
    a_smooth(ind) = a(i);
    b_smooth(ind) = b(i);
    ind = ind + 1;
  end
end

f_smooth
a_smooth
b_smooth

p = 1;
for i = 1:length(a_smooth)
  sum_bases = f_smooth(i,:);
  sum_b = b_smooth(i);
  sum_a = a_smooth(i);
  if(all(not(mod(sum_bases(:),2))))
    p = gcd(sum_a - sum_b, n);
    if((p != 1) && (p != n))
      break;
    end
  end
    
  for j = i + 1:length(a_smooth)
    sum_bases = f_smooth(i,:);
    sum_b = b_smooth(i);
    sum_a = a_smooth(i);
    for k = j:length(a_smooth)
      sum_b = sum_b * b_smooth(k);
      sum_a = mod(sum_a * a_smooth(k), n);
      sum_bases = sum_bases + f_smooth(k,:);
      if(all(not(mod(sum_bases(:),2))))
        p = gcd(sum_a - sqrt(sum_b), n);
        if((p != 1) && (p != n))
          break;
        end
      end
    end
    if((p != 1) && (p != n))
      break;
    end
  end
  if((p != 1) && (p != n))
    break;
  end
end


if((p != 1) && (p != n))
  p
  q = n/p
else
  disp("nothing found :(");
end