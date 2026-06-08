import pandas as pd
from sklearn.neighbors import KNeighborsClassifier
import joblib

# dataset MVP sederhana
data = [
    # packet_count, byte_count, duration, label
    [10, 800, 2, 0],
    [15, 1200, 3, 0],
    [20, 1600, 2, 0],
    [25, 2000, 4, 0],
    [30, 2500, 5, 0],
    [35, 2800, 5, 0],
    [40, 3200, 6, 0],
    [50, 4000, 6, 0],

    [500, 50000, 2, 1],
    [800, 90000, 2, 1],
    [1200, 140000, 3, 1],
    [2000, 250000, 3, 1],
    [5000, 700000, 4, 1],
    [10000, 1500000, 5, 1],
    [50000, 7000000, 6, 1],
    [200000, 22000000, 8, 1],
]

df = pd.DataFrame(data, columns=["packet_count", "byte_count", "duration", "label"])

X = df[["packet_count", "byte_count", "duration"]]
y = df["label"]

model = KNeighborsClassifier(n_neighbors=3)
model.fit(X, y)

joblib.dump(model, "knn_model.pkl")
print("Model saved as knn_model.pkl")

