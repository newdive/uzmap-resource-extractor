# uzmap-resource-extractor
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python 3.x](https://img.shields.io/badge/python-3.x-blue.svg)](https://github.com/python/cpython/tree/master)

<br><u>用于解密和提取apicloud apk下的资源文件(html, js ,css)</u>
### 背景&说明 ###
本人平时分析这类h5 app的时候，经常需要提取html, css, js等资源文件。  然而目前没有便捷的方法(有些通过xpose hook的方式提取，但比较麻烦)
<br>所以我针对同类app分析, 同时也对其中的libsec.so文件进行逆向，发现是使用rc4方式加密，而且密钥可以静态提取，所以写了这个工具方便快速提取资源文件
<br>项目的 [resources](https://github.com/newdive/resources) 文件夹中附带了apk和libsec.so的文件样本，供参考分析。 
<br>如果后续的加密方式有修改而导致不适用，可以提issue，也特别欢迎各位有志之士添砖加瓦
<br>这个工具仅供个人研究学习使用。 其它非法用途所造成的法律责任，一律与本项目无关。

### Note ###
  这个分支的目的

- 1、可以作为 AndroidNativeEmu 的一个应用案例， 方便学习研究

- 2、可以避开解密算法细节，具有更广的适用范围。(当然会有一定效率上的牺牲)

### Setup ###
先安装项目的依赖
```
pip install -r requirements.txt
```

由于依赖 AndroidNativeEmu 项目, 需要安装相关的依赖
```
cd emu_support/AndroidNativeEmu

pip install -r requirements.txt
```

- 支持pycryptodome, 让解密更高效

  ```
  pip install -r optional-requirements.txt
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
  
- 支持批量识别和解密 可以指定文件夹，会自动扫描文件夹下的所有 apicloud apk 并执行识别或解密

   ```python main.py -v targetFolder```



