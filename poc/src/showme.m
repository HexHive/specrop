function showme
  samples = csvread('attacker_samples.csv'); % Organized NSAMPLES columns, NCHARS*8 rows
  secret = csvread('secret_bits.csv');       % Organized 8 columns, NCHARS rows

  nchars = size(secret)(1)
  nbits = size(secret)(2)
  nsamples = size(samples)(2)

  % Transform into NCHARS x NSAMPLES x NBITS
  samples = permute(reshape(samples, nbits, [], nsamples), [2 3 1]);

  % hist_range = [60:1:100];
  figure
  for bit = 1:nbits
    data = samples(:, :, bit);                      % NCHARS x NSAMPLES
    secret_for_bit = secret(:, bit);                % NCHARS x 1

    subplot(2, 4, bit)
    plot_one_bit(data, secret_for_bit, 2);  
    title(strcat('(Means) Bit ', num2str(bit - 1)), 'fontsize', 20)
  endfor

  % for bit = 1:nbits
  %   data = samples(:, :, bit);                      % NCHARS x NSAMPLES
  %   secret_for_bit = secret(:, bit);                % NCHARS x 1

  %   subplot(4, 4, bit + 8)
  %   plot_one_bit(data, secret_for_bit, 1); 
  %   title(strcat('(Medians) Bit ', num2str(bit - 1)), 'fontsize', 20)
  % endfor

  
  print('hist.png', '-dpng', '-r300', '-S3600,2400');
endfunction

function plot_one_bit (data, secretv, which_stat)
  % Collapse samples by statistic
  if (which_stat == 1)
    summary_data = median(data, 2);               % NCHARS x 1
  elseif (which_stat == 2)
    summary_data = mean(data, 2);                 % NCHARS x 1
  elseif (which_stat == 3)
    summary_data = prctile(data, 90, 2) - prctile(data, 10, 2);          % NCHARS x 1
  endif

  q01 = floor(prctile(summary_data, 1)) - 5;
  q99 = ceil(prctile(summary_data, 99)) + 5;

  hist_range = [q01:1:q99];
  % Sort based on actual secret
  zero_idx = find(~secretv);
  ones_idx = find(secretv);

  data0 = summary_data(zero_idx);
  data1 = summary_data(ones_idx);

  % Calculate pdfs
  [hist0, b0] = hist(data0, hist_range);
  [hist1, b1] = hist(data1, hist_range);
  pdf0 = hist0 / size(data0)(1);
  pdf1 = hist1 / size(data1)(1);
  
  % Calculate accuracy over different threshold
  size0 = size(data0)(1);
  size1 = size(data1)(1);
  correct0 = sum(repmat(data0, 1, size(hist_range)(2)) >= repmat(hist_range, size0, 1), 1) / size0;
  correct1 = sum(repmat(data1, 1, size(hist_range)(2)) < repmat(hist_range, size1, 1), 1) / size1;
  correct = (size0 * correct0 + size1 * correct1) / (size0 + size1);
  
  % Threshold which maximizes correctness
  [max_cor threshold_idx] = max(correct');
  threshold = hist_range(threshold_idx);

  % Plot it all
  plot(b0, pdf0, 'LineWidth', 4, b1, pdf1, 'LineWidth', 4, b0, correct, 'LineWidth', 4, b0, correct0, 'LineWidth', 4, b0, correct1, 'LineWidth', 4);
  line([threshold threshold], [0 1]);
  ylabel ('Number of samples', 'fontsize', 20);
  if (which_stat == 1)
    xlabel ('Timestamp counter difference (median)', 'fontsize', 20);
  else
    xlabel ('Timestamp counter difference (mean)', 'fontsize', 20);
  endif
  set(gca, 'fontsize', 15);
  max_acc_str = strcat("Max accuracy ", num2str(max_cor), ' at threshold ', num2str(threshold))
  text(hist_range(1), 0.9, max_acc_str, 'fontsize', 20);

  h = legend('secret = 0', 'secret = 1', 'total accuracy', 'accuracy 0', 'accuracy 1');
  set(h, 'fontsize', 15);
  grid minor on

endfunction