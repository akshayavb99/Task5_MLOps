#!/usr/bin/env python
# coding: utf-8

# In[1]:


import re
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn import metrics
from scipy.spatial.distance import cdist
import numpy as np
from sklearn.cluster import KMeans 
import os


# In[2]:


d1 = pd.read_csv('/root/mlops_task5/access_log',header=None,names=['C1','C2'])
d1


# In[3]:


d1['IP_Address']=d1.C1.apply( lambda x: pd.Series(str(x).split(" ")))[0]
d1['Time']=d1.C1.apply( lambda x: pd.Series(str(x).split(" ")))[3]
d1['Time']=d1.Time.apply( lambda x: pd.Series(str(x).split("[")))[1]
d1['Method']=d1.C1.apply( lambda x: pd.Series(str(x).split(" ")))[5]
d1['Method']=d1.Method.apply( lambda x: pd.Series(str(x).split('\"')))[1]
d1['Resource']=d1.C1.apply( lambda x: pd.Series(str(x).split(" ")))[6]
d1['Protocol']=d1.C1.apply( lambda x: pd.Series(str(x).split(" ")))[7]
d1['Protocol']=d1.Protocol.apply( lambda x: pd.Series(str(x).split('\"')))[0]
d1['Status']=d1.C1.apply( lambda x: pd.Series(str(x).split(" ")))[8]
d1


# In[4]:


dataset=d1.drop(labels=['C1','C2'],axis=1)
dataset


# In[5]:


print(dataset.isnull().sum())
print()
print(dataset.nunique())
print()
dataset.Method.unique()


# In[6]:


indexNames = dataset[ dataset['Method'] == '-' ].index
# Delete these row indexes from dataFrame
dataset.drop(indexNames , inplace=True)
dataset


# In[7]:


dataset=dataset.drop(labels=['Time','Resource','Protocol'],axis=1)
dataset


# In[8]:


dataset.Status.unique()


# In[9]:


grouped_data=dataset.groupby(['IP_Address','Method','Status']).size().reset_index(name="access_counts")
#From above table, we can identify easily which IP is sending the DDOS attack from. 
plt.bar(grouped_data.IP_Address, grouped_data.access_counts, tick_label = grouped_data.IP_Address, width = 0.8)


# In[10]:


lb_enc=LabelEncoder()
train_data=grouped_data.copy()
train_data.IP_Address=lb_enc.fit_transform(train_data.IP_Address)
train_data


# In[11]:


train_data=train_data.drop(labels=['Method','Status'],axis=1)
sc=StandardScaler()
train_data=sc.fit_transform(train_data)
train_data


# In[12]:


distortions = []
K = range(1,5)
for k in K:
    kmeanModel = KMeans(n_clusters=k).fit(train_data)
    kmeanModel.fit(train_data)
    distortions.append(sum(np.min(cdist(train_data, kmeanModel.cluster_centers_, 'euclidean'), axis=1)) / train_data.shape[0])

plt.plot(K, distortions, 'bx-')
plt.xlabel('k')
plt.ylabel('Distortion')
plt.title('The Elbow Method showing the optimal k')
plt.show()


# In[13]:


from sklearn.cluster import KMeans 
#Creating Model 
seed = 42
model = KMeans(n_clusters=2,random_state=seed) 
#Fit and Predict 
pred = model.fit_predict(train_data) 
#Adding Cluster Labels to dataset 
grouped_data['Cluster']=pred
grouped_data


# In[14]:


#Blocking IPs
with open("/root/mlops_task5/blocked_ips.txt","a+") as f:
    print(f.read())
    for i in grouped_data.index:
        if grouped_data['Cluster'][i] == 1:
            print("Blocked IP : "+grouped_data['IP_Address'][i])
            f.seek(0)
            if grouped_data['IP_Address'][i] in f.read():
                print("Already present")
            else:
                print("New IP is added to the list")
                f.write(grouped_data['IP_Address'][i]+"\n")
f.close()


# In[ ]:





# In[ ]:




