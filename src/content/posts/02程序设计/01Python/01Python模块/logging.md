---
title: "logging"
date: 2025-07-26
tags:
  - Others
categories:
  - Others
---
# !未整理

```python
# logging 模块 记录 log 记录日志的模块

import logging
import logging.config
import os
import sys

try:
    # 想要给日志上色就安装这个模块
    # pip install coloredlogs :::>>> 给日志上个色
    import coloredlogs
except Exception as e:
    if str(e) == "No module named 'coloredlogs'":
        pass

# 自定义日志级别
CONSOLE_LOG_LEVEL = "INFO"
FILE_LOG_LEVEL = "DEBUG"

# 自定义日志格式
# 打印在文件里的格式：时间戳 + 线程名 + 线程ID + 任务ID + 发出日志调用的源文件名 + 发出日志调用的源代码行号 + 日志级别 + 日志消息正文
# [2023-06-04 15:16:05][MainThread:22896][task_id:root][调用.py:12][INFO][这是注册功能]
STANDARD_FORMAT = '[%(asctime)s][%(threadName)s:%(thread)d][task_id:%(name)s][%(filename)s:%(lineno)d][%(levelname)s][%(message)s]'
# 打印在控制台的格式：日志级别 + 时间戳 + 发出日志调用的源文件名 + 发出日志调用的源代码行号 + 日志消息正文
# [INFO][2023-06-04 15:37:28,019][调用.py:12]这是注册功能

SIMPLE_FORMAT = '[%(levelname)s][%(asctime)s][%(filename)s:%(lineno)d]%(message)s'
'''
参数详解:
-1.%(asctime)s: 时间戳，表示记录时间
-2.%(threadName)s: 线程名称
-3.%(thread)d: 线程ID
-4.task_id:%(name)s: 任务ID，即日志记录器的名称
-5.%(filename)s: 发出日志调用的源文件名
-6.%(lineno)d: 发出日志调用的源代码行号
-7.%(levelname)s: 日志级别，如DEBUG、INFO、WARNING、ERROR、CRITICAL等
-8.%(message)s: 日志消息正文
'''

# 日志文件路径
BASE_DIR = os.path.dirname(__file__)
# os.getcwd() : 获取当前工作目录，即当前python脚本工作的目录路径
# 拼接日志文件路径 : 当前工作路径 + “logs”(日志文件路径)
LOG_PATH = os.path.join(BASE_DIR, "logs")
# OS模块 ： 创建多层文件夹
# exist_ok=True 的意思是如果该目录已经存在，则不会抛出异常。
os.makedirs(LOG_PATH, exist_ok=True)
# log日志文件路径 ： 路径文件夹路径 + 日志文件
LOG_FILE_PATH = os.path.join(LOG_PATH, 'Logs.log')

# 日志配置字典
LOGGING_DIC = {
    # 日志版本
    'version': 1,
    # 表示是否要禁用已经存在的日志记录器（loggers）。
    # 如果设为 False，则已经存在的日志记录器将不会被禁用，而是可以继续使用。
    # 如果设为 True，则已经存在的日志记录器将会被禁用，不能再被使用。
    'disable_existing_loggers': False,
    # 格式化程序：用于将日志记录转换为字符串以便于处理和存储。
    # 格式化程序定义了每个日志记录的输出格式，并可以包括日期、时间、日志级别和其他自定义信息。
    'formatters': {
        # 自定义格式一：年-月-日 时:分:秒
        'standard': {
            # 自定义日志格式 ：时间戳 + 线程名 + 线程ID + 任务ID + 发出日志调用的源文件名 + 发出日志调用的源代码行号 + 日志级别 + 日志消息正文
            # 这里要对应全局的 STANDARD_FORMAT 配置
            'format': STANDARD_FORMAT,
            # 时间戳格式：年-月-日 时:分:秒
            'datefmt': '%Y-%m-%d %H:%M:%S'  # 时间戳格式
        },
        # 自定义格式二：
        'simple': {
            # 自定义日志格式：# 日志级别 + 时间戳 + 发出日志调用的源文件名 + 发出日志调用的源代码行号 + 日志消息正文
            # 这里要对应全局的 SIMPLE_FORMAT 配置
            'format': SIMPLE_FORMAT
        },
    },
    # 过滤器
    'filters': {},
    # 日志处理器
    'handlers': {
        # 自定义处理器名称 - 输出到控制台屏幕
        'console': {
            # 设置日志等级 为INFO
            'level': CONSOLE_LOG_LEVEL,
            # 表示该处理器将输出日志到流（stream）：日志打印到控制台
            'class': 'logging.StreamHandler',
            # 日志打印格式：日志级别 + 时间戳 + 发出日志调用的源文件名 + 发出日志调用的源代码行号 + 日志消息正文
            # 这里的配置要对应 formatters 中的 simple 配置
            'formatter': 'simple'
        },
        # 自定义处理器名称 - 输出到文件
        'default': {
            # 自定义日志等级
            'level': FILE_LOG_LEVEL,
            # 标准输出到文件
            'class': 'logging.handlers.RotatingFileHandler',
            # 日志打印格式：年-月-日 时:分:秒
            # 这里的配置要对应 formatters 中的 standard 配置
            'formatter': 'standard',
            # 这里 要注意声明配置文件输出端的文件路径
            'filename': LOG_FILE_PATH,
            # 限制文件大小：1024 * 1024 * 5 = 5242880，意味着这个变量的值是 5MB（兆字节）
            'maxBytes': 1024 * 1024 * 5,
            # 表示保留最近的5个日志文件备份。
            # 当日志文件达到最大大小限制时，将会自动轮转并且保留最新的5个备份文件，以便查看先前的日志记录。
            # 当日志文件达到最大大小限制时，会自动进行轮转，后续的文件名将会以数字进行命名，
            # 例如，第一个备份文件将被重命名为原始日志文件名加上".1"的后缀，
            # 第二个备份文件将被重命名为原始日志文件名加上“.2”的后缀，
            # 以此类推，直到保留的备份数量达到设定的最大值。
            'backupCount': 5,
            # 日志存储文件格式
            'encoding': 'utf-8',
        },
    },
    # 日志记录器，用于记录应用程序的运行状态和错误信息。
    'loggers': {
        # 空字符串作为键 能够兼容所有的日志(当没有找到对应的日志记录器时默认使用此配置)
        # 默认日志配置
        '': {
            # 日志处理器 类型：打印到控制台输出 + 写入本地日志文件
            'handlers': ['default', 'console'],
            # 日志等级 ： DEBUG
            'level': 'DEBUG',
            # 默认情况下，当一个日志消息被发送到一个Logger对象且没有被处理时，该消息会被传递给它的父Logger对象，以便在更高层次上进行处理。
            # 这个传递过程称为“传播(propagation)”，而propagate参数指定了是否要使日志消息向上传播。
            # 将其设置为True表示应该传播消息到上一级的Logger对象；如果设置为False则不传播。
            # 表示异常将会在程序中继续传播
            # 也就是说，如果一个异常在当前的代码块中没有被处理，它将会在上级代码块或调用函数中继续向上传递，直到被某个代码块捕获或者程序退出。
            # 这是 Python 中异常处理机制的默认行为。
            # 如果将 'propagate' 设置为 False，则异常不会被传播，即使在上级代码块中没有处理异常的语句，程序也会忽略异常并继续执行。
            'propagate': True,
        },
    },
}


def set_logging_color(name='', ):
    # 初始化日志处理器 - 使用配置字典初始化日志处理器(将自定义配置加载到日志处理器中)
    # logging.basicConfig(level=logging.WARNING)
    logging.config.dictConfig(LOGGING_DIC)
    # 实例化日志处理器对象 - 并赋予日志处理器等级
    logger = logging.getLogger(name)
    # 将logger对象传递给coloredlogs.install()函数，并执行该函数以安装彩色日志记录器，使日志信息在控制台上呈现为带有颜色的格式。
    # 具体来说，该函数会使用ANSI转义序列在终端上输出日志级别、时间戳和消息等信息，并按日志级别使用不同的颜色来区分它们。这可以让日志信息更易于阅读和理解。
    coloredlogs.install(logger=logger)
    # 禁止日志消息向更高级别的父记录器(如果存在)传递。
    # 通常情况下，当一个记录器发送一条日志消息时，该消息会被传递给其所有祖先记录器，直到传递到根记录器为止。但是，通过将logger.propagate设置为False，就可以阻止该记录器的消息向上层传递。
    # 换句话说，该记录器的消息只会被发送到该记录器的处理程序（或子记录器）中，而不会传递给祖先记录器，即使祖先记录器的日志级别比该记录器要低。
    # 这种方法通常适用于需要对特定记录器进行控制，并希望完全独立于其祖先记录器的情况。
    # 确保 coloredlogs 不会将我们的日志事件传递给根 logger，这可以防止我们重复记录每个事件
    logger.propagate = False
    # 配置 日志颜色
    # 这段代码定义了一个名为coloredFormatter的变量，并将其赋值为coloredlogs.ColoredFormatter。
    # 这是一个Python库中的类，用于创建带有彩色日志级别和消息的格式化器。
    # 该变量可以用作日志记录器或处理程序的格式化程序，以使日志输出更易于阅读和理解。
    coloredFormatter = coloredlogs.ColoredFormatter(
        # fmt表示格式字符串，它包含了一些占位符，用于在记录日志时动态地填充相关信息。
        # [%(name)s]表示打印日志时将记录器的名称放在方括号内，其中name是一个变量名，将被记录器名称所替换。
        # %(asctime)s表示打印日志时将时间戳（格式化为字符串）插入到消息中，其中asctime是时间的字符串表示形式。
        # %(funcName)s表示打印日志时将函数名插入到消息中，其中funcName是函数的名称。
        # %(lineno)-3d表示打印日志时将行号插入到消息中，并且将其格式化为3位数字，其中lineno表示行号。
        # %(message)s表示打印日志时将消息本身插入到消息中。
        # 综合起来，这个格式字符串将在记录日志时输出以下信息：记录器名称、时间戳、函数名称、行号和日志消息。
        # 记录器名称 + 时间戳 + 函数名称 + 行号 + 日志消息
        # [root] 2023-06-04 16:00:57 register 15   this is an info message
        fmt='[%(name)s] %(asctime)s %(funcName)s %(lineno)-3d  %(message)s',
        # 级别颜色字典
        level_styles=dict(
            # debug 颜色：白色
            debug=dict(color='white'),
            # info 颜色：蓝色
            info=dict(color='blue'),
            # warning 颜色：黄色 且 高亮
            warning=dict(color='yellow', bright=True),
            # error 颜色：红色 且 高亮 且 加粗
            error=dict(color='red', bold=True, bright=True),
            # critical 颜色：灰色 且 高亮 且 背景色为红色
            critical=dict(color='black', bold=True, background='red'),
        ),
        # 这段代码定义了一个名为field_styles的字典 , 其中包含四个键值对。
        # 每个键代表日志记录中的不同字段，而每个值是一个字典，它指定了与该字段相关联的样式选项。
        # 具体来说，这些字段和样式选项如下：
        # name：指定记录器的名称，将使用白色颜色。
        # asctime：指定日志记录的时间戳，将使用白色颜色。
        # funcName：指定记录消息的函数名称，将使用白色颜色。
        # lineno：指定记录消息的源代码行号，将使用白色颜色。
        field_styles=dict(
            name=dict(color='white'),
            asctime=dict(color='white'),
            funcName=dict(color='white'),
            lineno=dict(color='white'),
        )
    )

    ## 配置 StreamHandler：终端打印界面
    # 这行代码定义了一个名为ch的日志处理器。
    # 具体来说，它是logging.StreamHandler类的一个实例，用于将日志输出到标准输出流（即控制台）中。
    # 在创建StreamHandler对象时，需要指定要使用的输出流
    # 因此stream=sys.stdout参数指定了该对象将把日志写入到标准输出流中.
    ch = logging.StreamHandler(stream=sys.stdout)
    # 这段代码是 Python 中用于设置日志输出格式的语句。
    # 它使用了一个名为 coloredFormatter 的格式化器对象，并将其传递给 ch.setFormatter() 方法来指定输出日志的样式。
    # 具体来说，ch 是一个 Logger 对象，它代表了整个日志系统中的一个记录器。
    # 可以通过该对象来控制日志的级别、输出位置等行为。而 setFormatter() 方法则用于设置该 Logger 输出日志的格式化方式
    # 这里传递的是 coloredFormatter 格式化器对象。
    # 在实际应用中，coloredFormatter 可以是自定义的 Formatter 类或者已经存在的 Formatter 对象。
    # 这里 将 coloredFormatter - 彩色输出日志信息的格式化器 传入进去。
    ch.setFormatter(fmt=coloredFormatter)
    # 这段代码是在Python中添加一个日志记录器（logger）的处理器（handler）。其中，hdlr参数是指定要添加到记录器(logger)中的处理器(handler)对象，ch是一个代表控制台输出的处理器对象。
    # 这行代码的作用是将控制台输出的信息添加到日志记录器中。
    logger.addHandler(hdlr=ch)
    # 这段代码用于设置日志级别为DEBUG，也就是最低级别的日志记录。
    # 意思是在程序运行时，只有DEBUG级别及以上的日志信息才会被记录并输出，而比DEBUG级别更低的日志信息则不会被记录或输出。
    # DEBUG（调试）、INFO（信息）、WARNING（警告）、ERROR（错误）和CRITICAL（严重错误）。
    logger.setLevel(level=logging.DEBUG)
    # 返回日志生成对象
    return logger


def get_logger(name='', ):
    '''
    :param name: 日志等级
    :return:
    '''
    # 初始化日志处理器 - 使用配置字典初始化日志处理器(将自定义配置加载到日志处理器中)
    logging.config.dictConfig(LOGGING_DIC)
    # 实例化日志处理器对象 - 并赋予日志处理器等级
    logger = logging.getLogger(name)
    # 返回日志生成对象
    return logger


if __name__ == "__main__":
    # # 示例：
    # # （1）初始化日志处理器 - 使用配置字典初始化日志处理器(将自定义配置加载到日志处理器中)
    # logging.config.dictConfig(LOGGING_DIC)
    # # （2）实例化日志处理器对象 - 并赋予日志处理器等级
    # # # logger1 = logging.getLogger('') # 默认为 '' 即以默认配置进行实例化
    # logger1 = logging.getLogger('')
    # # （3）当日志发生时，打印的提示语
    # logger1.debug('这是日志生成语句')
    logger_nor = get_logger(name='user')
    logger_nor.info(msg="this is a info message")
    logger_col = set_logging_color()
    logger_col.info(msg="this is a debug message")

```