#6
import numpy as np
import matplotlib.pyplot as plt

initial_values = np.random.randint(0, 2**32, size=89)
x = list(initial_values)

m = 2**32

def additive_generator(length):
    results = []
    for i in range(length):
        x_next = (x[-38] + x[-89]) % m
        x.append(x_next)
        results.append(x_next)
        x.pop(0)
    return results

sequence_length = 10000
sequence = additive_generator(sequence_length)

mean_value = np.mean(sequence)
plt.figure(figsize=(12, 5))
plt.hist(sequence, bins=50, color='blue', alpha=0.7)
plt.axvline(mean_value, color='red', linestyle='dashed', linewidth=1)
plt.title('Распределение значений и среднее значение')
plt.xlabel('Значение')
plt.ylabel('Частота')
plt.show()

def autocorrelation(seq, lag):
    return np.corrcoef(seq[:-lag], seq[lag:])[0, 1]

lags = range(1, 100)
autocorrelations = [autocorrelation(sequence, lag) for lag in lags]

plt.figure(figsize=(12, 5))
plt.plot(lags, autocorrelations, marker='o')
plt.title('Автокорреляция последовательности')
plt.xlabel('Lag')
plt.ylabel('Автокорреляция')
plt.show()

def find_period(seq):
    for p in range(1, len(seq)//2):
        if seq[:p] == seq[p:2*p]:
            return p
    return None

period = find_period(sequence)
if period:
    print(f"Период последовательности: {period}")
else:
    print("Период не найден в пределах длины последовательности")

cumulative_mean = np.cumsum(sequence) / np.arange(1, len(sequence) + 1)
plt.figure(figsize=(12, 5))
plt.plot(sequence, label='Последовательность', alpha=0.5)
plt.plot(cumulative_mean, label='Среднее значение', color='red', linestyle='dashed')
plt.title('Последовательность и её среднее значение')
plt.xlabel('Номер элемента')
plt.ylabel('Значение')
plt.legend()
plt.show()
