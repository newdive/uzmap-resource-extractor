# uzmap-resource-extractor
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python 2.7](https://img.shields.io/badge/python-2.7-blue.svg)](https://github.com/python/cpython/tree/2.7)

<br><u>用于解密和提取apicloud apk下的资源文件(html, js ,css)</u>
### 背景&说明 ###
本人平时分析这类h5 app的时候，经常需要提取html, css, js等资源文件。  然而目前没有便捷的方法(有些通过xpose hook的方式提取，但比较麻烦)
<br>所以我针对同类app分析, 同时也对其中的libsec.so文件进行逆向，发现是使用rc4方式加密，而且密钥可以静态提取，所以写了这个工具方便快速提取资源文件
<br>项目的 [resources](https://github.com/newdive/resources) 文件夹中附带了apk和libsec.so的文件样本，供参考分析。 
<br>如果后续的加密方式有修改而导致不适用，可以提issue，也特别欢迎各位有志之士添砖加瓦
<br>这个工具仅供个人研究学习使用。 其它非法用途所造成的法律责任，一律与本项目无关。
### Note ###
本分支支持```python2.7``` <br>
```master``` 分支支持 ```python3.x```<br>


### Setup ###
先安装项目的依赖
```
pip install requirements
```

### Usage ###
```
python main.py xxx.apk
```
支持参数列表通过 -h查看
```
python main.py -h
```

具体用例

- 查看apk中的rc4密钥

  ```python main.py -v xxx.apk ```
    
  输出信息说明
   ```
        package      : xxx.ooo.xxx              ==> 应用包名
        uz_version   : 1.3.13                   ==> apicloud engine的版本号
        encrypted    : False                    ==> 资源是否加密
        rc4Key       : xxxxxxxxxxxxxxxxxxxx     ==> 资源加密用到的RC4密钥
    ```

- 解密并提取所有的资源文件(如果不指明输出路径 默认输出到apk所在的文件夹下)

  ```python main.py -o 输出路径 xxx.apk ```

