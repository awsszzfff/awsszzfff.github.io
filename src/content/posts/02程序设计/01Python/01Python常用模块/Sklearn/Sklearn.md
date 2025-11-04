---
title: "Sklearn"
date: 2025-02-11
tags:
  - Others
categories:
  - Others
---
【特征提取，特征处理】

```python file:3.4.2-Scikit-learn
from sklearn.preprocessing import StandardScaler
scaler = StandardScaler()
scaler.fit_transform(data)

from sklearn.preprocessing import MinMaxScaler
scaler = MinMaxScaler()
scaler.fit_transform(data)

correlations = data.corr().abs()
features = correlations[correlations['C'] > 0.5].index.tolist()

from sklearn.decomposition import PCA
pca = PCA(n_components=2)
data_pca = pca.fit_transform(data)
```

> 参考学习
> 
> https://www.runoob.com/sklearn/sklearn-tutorial.html
> 
> https://sklearn.woshicver.com/