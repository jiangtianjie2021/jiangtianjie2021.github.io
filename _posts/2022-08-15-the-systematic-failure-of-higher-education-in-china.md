---
layout:     post
title:      "Guns详解"
subtitle:   "guns"
date:       2022-08-14 12:00:00
author:     "JtJ"
catalog: false
published: false
header-style: text
tags:
  - Vim
  - Emacs
---

# 权限设计

## system业务

System模块的各个业务介绍：

| **模块名**                   | **功能详情**                   |
| ---------------------------- | ------------------------------ |
| system-business-app          | 应用管理。应用是菜单的大分类。 |
| system-business-menu         | 菜单管理。左侧菜单的管理。     |
| system-business-notice       | 通知管理。                     |
| system-business-organization | 组织机构管理。                 |
| system-business-resource     | 资源管理。资源对应了接口。     |
| system-business-role         | 角色管理。                     |
| system-business-user         | 用户管理。                     |
| system-integration-beetl     | beetl项目集成。                |
| system-integration-rest      | restful项目集成。              |
| system-spring-boot-starter   | spring boot自动配置。          |

用户管理、职位管理、应用管理、角色管理、菜单管理

![img](https://cdn.nlark.com/yuque/0/2022/png/25441324/1654771288907-8614dcaf-ff35-44c5-a399-1251f1737b5b.png)![img](https://cdn.nlark.com/yuque/0/2022/png/25441324/1654776503045-404f2d00-c877-4beb-9da1-08f84ac04dcb.png)

**认证是校验用户能否登录系统，认证的过程是校验token的过程**

**鉴权是校验用户有系统的哪些权限，鉴权的过程是校验角色是否包含某些接口的权限**

用户、角色、菜单、按钮、接口

用户绑定角色，角色绑定菜单，菜单绑定按钮和接口，按钮也可以绑定接口。

用户——接口、按钮

## 认证过程

认证的拦截器是 AuthJwtTokenSecurityInterceptor

如果接口需要认证才可以访问，则用户必须携带合法token在以下任意一个位置即可：

1. 1. 请求参数的param中，参数名为token
   2. 请求的header中，参数名为Authorization
   3. 请求的cookie中，参数名为Authorization

如果token未过期，并且是由系统合法颁发的即可通过认证。

**认证并非只校验jwt token本身规则否合法，还会校验会话是否存在。**

在用户登录过程中，会调用SessionManagerApi.createSession()进行会话创建，每一个登录用户会有对应一个会话。

会话的管理可以让在线用户的管控更加方便：

1. 1. 可以查看到当前登录系统的用户信息
   2. 当用户发生不正常操作时，可以将用户踢下线

SessionManagerApi会话管理接口还有一些其他常用方法，例如刷新会话，更新会话信息，删除会话，获取所有会话信息等。

使用时，直接注入SessionManagerApi即可使用。

## 鉴权过程

鉴权的拦截器是 PermissionSecurityInterceptor

鉴权的核心过程是：

1. 1. 获取当前用户所有的的资源url的权限List
   2. 然后和当前请求url进行比对
   3. 如果List中有url则代表用户有对应的权限，放行请求
   4. 如果List中没用url，则代表没有对应权限，拦截请求

核心验证过程在 PermissionServiceApi checkPermission()方法

## 相关配置

打开基础数据-系统配置，可以找到鉴权配置这个模块有一些配置。这些配置也在sys_config表中存在。

| **配置项**                        | **描述**                                                     |
| --------------------------------- | ------------------------------------------------------------ |
| session过期时间                   | 默认是3600秒，也就是当前用户没有在界面上操作的情况下，多久就会被踢下线。 |
| 账号单端登录限制                  | 默认是false，当改为true以后，同一时刻一个人的账号只能在一个浏览器登录。 |
| 系统默认密码                      | 一般用在重置系统的默认密码。                                 |
| 用于auth模块权限校验的jwt失效时间 | jwt token本身的失效时间，不是会话过期时间，一般比会话过期时间大。 |
| auth认证用的jwt秘钥               | jwt token生成时候的jwt秘钥，一般在第一次进页面时候会自动生成一个随机字符串。 |

## 数据权限

**数据权限**指的是针对数据列表展示过程中，**根据当前用户数据范围的不同，展示出不同数据内容的过滤**。

### 1. 配置数据范围

在角色管理可以进行数据权限的在线配置：

### 2. 使用数据范围

配置好角色的数据范围之后，并不是所有的业务都会自动过滤数据范围。需要在程序中进行数据范围过滤。参考这段代码，这段代码是用户管理进行数据范围过滤的代码。

```java
// 获取当前用户数据范围的枚举
Set<DataScopeTypeEnum> dataScopeTypeEnums = loginUser.getDataScopeTypeEnums();

// 获取当前用户数绑定的组织机构范围
Set<Long> dataScopeOrganizationIds = loginUser.getDataScopeOrganizationIds();

// 获取当前用户绑定的用户数据范围
Set<Long> dataScopeUserIds = loginUser.getDataScopeUserIds();

// 如果包含了全部数据
if (dataScopeTypeEnums.contains(DataScopeTypeEnum.ALL)) {
    sysUserRequest.setScopeOrgIds(null);
    sysUserRequest.setUserScopeIds(null);
}
// 如果是按部门数据划分
else if (dataScopeTypeEnums.contains(DataScopeTypeEnum.DEPT)
         || dataScopeTypeEnums.contains(DataScopeTypeEnum.DEPT_WITH_CHILD)
         || dataScopeTypeEnums.contains(DataScopeTypeEnum.DEFINE)) {
    sysUserRequest.setScopeOrgIds(dataScopeOrganizationIds);
    sysUserRequest.setUserScopeIds(null);
}
// 如果包含了仅有自己的数据
else if (dataScopeTypeEnums.contains(DataScopeTypeEnum.SELF)) {
    sysUserRequest.setScopeOrgIds(null);
    sysUserRequest.setUserScopeIds(dataScopeUserIds);
}
// 其他情况，没有设置数据范围，则查所有
else {
    sysUserRequest.setScopeOrgIds(null);
    sysUserRequest.setUserScopeIds(null);
}
```

之后，在编写Mybatis的Wrapper或者Mybatis的Mapping.xml中，可以响应拼接上对组织机构id的过滤。

```java
LambdaQueryWrapper<HrOrganization> wrapper = new LambdaQueryWrapper<>();
wrapper.in(HrOrganization::getOrgId, dataScopeOrganizationIds);
<if test="sysUserRequest.scopeOrgIds != null and sysUserRequest.scopeOrgIds.size() > 0">
  and suorg.org_id in
  <foreach  item="item" collection="sysUserRequest.scopeOrgIds" index="index"  open="(" separator="," close=")">
    #{item}
  </foreach>
</if>
<if test="sysUserRequest.userScopeIds != null and sysUserRequest.userScopeIds.size() > 0">
  and suser.user_id in
  <foreach  item="item" collection="sysUserRequest.userScopeIds" index="index"  open="(" separator="," close=")">
    #{item}
  </foreach>
</if>
```

## JWT插件

### 1. 设计目的

jwt提供了一种简单的，无状态的认证校验方式。在API认证等场景下非常有效。

关于jwt介绍的文章，可以参考如下：https://www.jianshu.com/p/576dbf44b2ae

Guns本身的认证不单纯用的**jwt**，还用了基于**会话**的机制，**双重校验用户合法性**。

### 2. 相关接口

```java
/**
* jwt相关的操作api
*
* @author fengshuonan
* @date 2020/10/21 11:31
*/
public interface JwtApi {
    
    /**
    * 生成token
    *
    * @param payload jwt的载体信息
    * @return jwt token
    * @author fengshuonan
    * @date 2020/10/21 11:38
    */
    String generateToken(Map<String, Object> payload);
    
    /**
    * 生成token，用默认的payload格式
    *
    * @param defaultJwtPayload jwt的载体信息
    * @return jwt token
    * @author fengshuonan
    * @date 2020/10/21 11:38
    */
    String generateTokenDefaultPayload(DefaultJwtPayload defaultJwtPayload);
    
    /**
    * 获取jwt的payload（通用的）
    *
    * @param token jwt的token
    * @return jwt的payload
    * @author fengshuonan
    * @date 2020/10/21 11:52
    */
    Map<String, Object> getJwtPayloadClaims(String token);
    
    /**
    * 获取jwt的payload（限定默认格式）
    *
    * @param token jwt的token
    * @return 返回默认格式的payload
    * @author fengshuonan
    * @date 2020/10/21 11:51
    */
    DefaultJwtPayload getDefaultPayload(String token);
    
    /**
    * 校验jwt token是否正确
    * <p>
    * 不正确的token有两种：
    * <p>
    * 1. 第一种是jwt token过期了
    * 2. 第二种是jwt本身是错误的
    * <p>
    * 本方法只会响应正确还是错误
    *
    * @param token jwt的token
    * @return true-token正确，false-token错误或失效
    * @author fengshuonan
    * @date 2020/10/21 11:43
    */
    boolean validateToken(String token);
    
    /**
    * 校验jwt token是否正确，如果参数token是错误的会抛出对应异常
    * <p>
    * 不正确的token有两种：
    * <p>
    * 1. 第一种是jwt token过期了
    * 2. 第二种是jwt本身是错误的
    *
    * @param token jwt的token
    * @throws JwtException Jwt相关的业务异常
    * @author fengshuonan
    * @date 2020/10/21 11:43
    */
    void validateTokenWithException(String token) throws JwtException;
    
    /**
    * 校验jwt token是否失效了
    *
    * @param token jwt token
    * @return true-token失效，false-token没失效
    * @author fengshuonan
    * @date 2020/10/21 11:56
    */
    boolean validateTokenIsExpired(String token);
    
}
```

### 3. 使用方法

第一种方法：

```java
JwtConfig jwtConfig=new JwtConfig();
jwtConfig.setJwtSecret("secret");
jwtConfig.setExpiredSeconds(3600L);
JwtApi jwtApi=new JwtTokenOperator(jwtConfig);
String jwt=jwtApi.generateToken(new HashMap<>());
```

第二种方法：

默认Guns中自动配置了一个JwtApi，直接注入也可使用。

```java
@Service
public class Test {

    @Resource
    private JwtApi jwtApi;

    public String test() {
        String jwtToken = jwtApi.generateToken(new HashMap<>());
    }
    
}
```

第二种方法的jwt秘钥在系统配置表中配置，配置名分别是：SYS_JWT_SECRET 和 SYS_JWT_TIMEOUT_SECONDS

```java
public class JwtConfigExpander {

    /**
     * 获取jwt的密钥
     *
     * @author fengshuonan
     * @date 2020/12/1 15:07
     */
    public static String getJwtSecret() {
        String sysJwtSecret = ConfigContext.me().getConfigValueNullable("SYS_JWT_SECRET", String.class);

        // 没配置就返回一个随机密码
        if (sysJwtSecret == null) {
            return RandomUtil.randomString(20);
        } else {
            return sysJwtSecret;
        }
    }

    /**
     * jwt失效时间，默认1天
     *
     * @author fengshuonan
     * @date 2020/12/1 15:08
     */
    public static Long getJwtTimeoutSeconds() {
        return ConfigContext.me().getSysConfigValueWithDefault("SYS_JWT_TIMEOUT_SECONDS", Long.class, DEFAULT_JWT_TIMEOUT_SECONDS);
    }

}
```

## Security插件

### 1. 拖拽验证码

项目中有两个验证码开关，拖拽验证码是给前后端分离的项目用的。

![img](https://cdn.nlark.com/yuque/0/2022/png/25441324/1658044636003-3a8de247-4071-44fc-b47c-0cfce4b2f2ac.png)

首先在系统配置菜单中打开这个开关。之后，前端项目也要打开这个开关才能用。

前端的配置在如下位置：

![img](https://cdn.nlark.com/yuque/0/2022/png/25441324/1658044652763-0dab133a-5e6f-49ec-aad9-b3037432101d.png)

打开之后，在登录时候会弹出拖拽验证码，从而进行人机验证，防止暴力破解。

![img](https://cdn.nlark.com/yuque/0/2022/png/25441324/1658044666673-61a83c9d-a6aa-46ff-af89-701971570b84.png)

### 2. 图形验证码

图形验证码是给前后端不分离项目使用，只需要在系统配置菜单中打开开关即可使用。

登录时候，如果打开了验证码开关，则会提示需要输入验证码，从而防止暴力破解。

![img](https://cdn.nlark.com/yuque/0/2022/png/25441324/1658044685480-0427c17f-5bcb-4d35-979f-06b81c634590.png)

### 跨域访问

项目中默认允许接口进行跨域访问，因为在CorsFilterConfiguration类中，默认配置了跨域访问。

### xss过滤器

XSS过滤器会过滤请求参数中非法的字段，例如携带html标签，script标签的请求将会被转移为特殊字符串。

**如果有需要放开某个接口的XSS过滤**，只需在系统配置菜单进行xss排除过滤url范围的配置即可。支持通配符配置。

跨站脚本攻击（也称为XSS）指利用网站漏洞从用户那里恶意盗取信息。

## SSO单点登录

### 1. 插件参数

| **插件属性** | **说明**      |
| ------------ | ------------- |
| 适用Guns版本 | Guns v7最新版 |
| 官方认证     | √             |
| 测试通过     | √             |
| 提供文档     | √             |
| v7同步更新   | √             |

### 2. 插件内容

SSO提供统一会话管理，用户只需要登录一次即可访问所有互相信任的系统。

支持**跨域名单点登录**，提供**单点认证服务器**，用户登录可直接经过SSO服务端，也支持客户端登录后再进行统一会话创建。

## SaaS多租户插件

### 1. 插件参数

| **插件属性** | **说明**      |
| ------------ | ------------- |
| 适用Guns版本 | Guns v7最新版 |
| 官方认证     | √             |
| 测试通过     | √             |
| 提供文档     | √             |
| v7同步更新   | √             |

### 2. 插件内容

提供基于数据库隔离方式的SAAS多租户运营系统。提供租户创建，不同维度用户的维护，不同维度数据的治理。

## 核心实现

### 数据库设计

![img](https://cdn.nlark.com/yuque/0/2022/png/25441324/1654840144757-64b6827c-44ed-427a-9d31-4314fd441882.png)![img](https://cdn.nlark.com/yuque/0/2022/png/25441324/1654840163832-5ff6b3c1-2eff-4f63-8a01-ebb50fa565d8.png)![img](https://cdn.nlark.com/yuque/0/2022/png/25441324/1654840188587-198fdbb0-91cb-4ec1-b84a-98beb58a7add.png)![img](https://cdn.nlark.com/yuque/0/2022/png/25441324/1654840383759-b2bf2ad5-e104-409e-bf61-0cf4ebc89e79.png)![img](https://cdn.nlark.com/yuque/0/2022/png/25441324/1654840238995-51a4e979-62d3-48e5-af91-f93c21b58f06.png)

用户（数据权限、组织、角色）角色（数据权限、菜单、菜单按钮、资源）组织、职位、菜单（按钮、资源）资源

### 代码设计

![img](https://cdn.nlark.com/yuque/0/2022/png/25441324/1654840623692-3556a636-c38a-422c-babe-bf25f091947a.png)![img](https://cdn.nlark.com/yuque/0/2022/png/25441324/1654840654406-36683fac-8990-49ab-831d-1e71a10e2203.png)![img](https://cdn.nlark.com/yuque/0/2022/png/25441324/1654840640690-31772129-4ba3-434d-a7d5-56d848744656.png)![img](https://cdn.nlark.com/yuque/0/2022/png/25441324/1654840678756-6efb7d61-9115-4608-ad02-7a26db40d558.png)![img](https://cdn.nlark.com/yuque/0/2022/png/25441324/1654840695264-9718ed33-dd71-40f0-be98-7008bbe9b80b.png)![img](https://cdn.nlark.com/yuque/0/2022/png/25441324/1654840720899-4c6aab45-4edd-4872-8b28-17139c4da1c9.png)

Organization中就是组织和职位的设定，仅工厂方法里面有一个组织的树形结构。

User记录着登录、在线管理、用户信息、用户管理这些模块，包含缓存、包装、工厂

Role中东西比User少一些，采用了缓存

Resource基本也是从数据库中获取，核心在切面和注解那里如何插入数据库，工厂里有转化和树形结构

Menu对应着按钮和资源，按钮有个常量，按钮后面再看

#### 异常

每个模块一个异常，模块异常继承自ServiceException（*所有业务异常的基类，继承自运行时异常，包括错误码、提示信息、模块名称、携带数据*）

每个模块有很多的枚举，继承自AbstractExceptionEnum（错误码和提示信息），依靠这个来区分不同的异常，模块名称自然是SystemConstants.*SYSTEM_MODULE_NAME*，数据可以有也可以没有。

错误码的设定，由rule模块下的规则（规则分为用户端操作异常、系统业务执行异常、第三方调用异常）加上自定义的步进值和依次的序号。

提示信息里面可以加上{}，使用时赋值参数，在模块异常的构造函数中也有相应的实现。

#### 缓存

用户、用户组织、用户角色分别实现内存和redis两种代码，分别继承自AbstractMemoryCacheOperator、AbstractRedisCacheOperator**（两个代码分别实现***缓存操作的基础接口-*CacheOperatorApi的各种功能**）**

采用泛型，泛型对应的实体类就是存储的value，redis依靠RedisTemplate，缓存依靠TimedCache。分别在构造函数将上述api作为参数引入。

在starter模块下，利用hutool的CacheUtil声明RedisTemplate和TimedCache，将其声明构造函数，并加入到bean容器中。因此可以直接在函数中依靠@Resource来获取到bean中的工具类。

缓存和redis分别如何实现以后再看

#### createWrapper

LambdaQueryWrapper<T>

#### 分页

PageFactory（*分页参数快速获取*）

PageResult（*分页结果封装*）

PageResultFactory（*分页的返回结果创建工厂*）*一般由mybatis-plus的Page对象转为PageResult*

常规mybatis-plus的分页（返回类 需要同样为 T，不能连表）

*mybatis-plus*的this.page(Page<T>, LambdaQueryWrapper<T>)

PageFactory.*defaultPage*()*默认分页，在使用时会自动获取pageSize和pageNo参数组成Page类*

PageResultFactory将生成的Page类转换成PageResult

需要连表查询，返回XXXDTO的分页

Page<XXXDTO> userPage = this.baseMapper.findUserPage(Page<T>, XXXRequest);

在Mapper中，@Param("page")便能默认为分页，然后在xml中实现逻辑，返回DTO实体。

#### 当前用户

用户数据范围枚举、用户数据范围用户信息、用户数据范围组织信息、可用资源集合、用户拥有的按钮编码集合

声明一个类LoginContext，里面通过反射获取LoginUserApi，LoginUserImpl实现getLoginUser：

1. 从线程池LoginUserHolder（*当前登录用户的临时保存容器*）尝试获取实体，在当前线程获取
2. 获取当前用户token，从sessionManagerApi中的loginUserCache（*登录用户缓存，key为token，value为*loginuser）中获取，依靠session一起维护用户的缓存

多线程，每登陆一个创建一个session

#### 登录

LoginController：loginApi——account、password

AuthServiceApi：loginAction（登录的真正业务逻辑）——LoginRequest、validatePassword、caToken

登录错误检测，判断错误次数，超过最大放入缓存中

获取用户密码的加密值和用户的状态

——userServiceApi.getUserLoginInfo()*获取用户登录的详细信息（用在第一次获取登录用户）*

获取LoginUser，用于用户的缓存

UserServiceApi：getUserLoginInfo（获取用户登录需要的详细信息（用在第一次获取登录用户））

用户

角色

数据范围

组织

资源

按钮



看这两个类所引用的，是否有影响，有一些影响，

#### 带着问题去看代码：

1. sys_user_org支持复写，会有什么影响

整个函数V2，并@Primary

SysUserOrgDTO也V2

*SysUserOrg改为List*

*UserOrgRequest不如也叫V2*

1. 新开一个表会有什么问题

效仿user和userorg，做一个新的模块，要学习一下user整体的模块

从学生的功能贴入，或者以老师用户在外面的引用切入。

student、studentorg



获取该用户能看到的组织树，然后点击来查看学生

学生分页查询

问题不大



登录、权限、缓存、apifox的实现





LoginResponse、UserLoginInfoDTO、LoginUser



SSO登录



多租户。

WPS后端支持。



数据库多层数据落库。考虑login的实现。

教师端的实现。



面对面建群——老师设计一个班级id，然后学生输入班级id然后进班。这个很后面。

# 日志设计

日志默认记录到库中

## 日志插件

### 1. 设计目的

日志是系统必不可少的组成部分，日志模块设计为了方便记录系统的业务日志和异常日志。

记录日志一般有两种办法。

### 2. slf4j

slf4j方式可以记录日志，日志输出在控制台和日志文件中。

使用方式很简单，在业务类上加@Slf4j注解（前提是ide要安装lombok插件）

![img](https://cdn.nlark.com/yuque/0/2022/png/25441324/1655269685153-66b94fe7-2bfb-41cc-bf3f-963ced264271.png)

然后类中使用log.xxx即可打印日志。 ![img](https://cdn.nlark.com/yuque/0/2022/png/25441324/1655269702650-56e38945-fefa-4730-b5ae-a5e6a4264ae2.png)

slf4j的日志配置在logback-spring.xml中，如果需要修改日志配置，则编辑此文件即可。

**local环境下，只输出到控制台，非local环境，一般输出到控制台+文件中**。

![img](https://cdn.nlark.com/yuque/0/2022/png/25441324/1655269758053-c64d8aa3-498c-4ddb-9e17-4d00fb9efcfa.png)

### 3. 日志api使用

日志API指的是LogRecordApi，这种方式区别于slf4j的方式，区别是可以将日志通过拓展不同实现记录到不同位置，例如数据库中。

![img](https://cdn.nlark.com/yuque/0/2022/png/25441324/1655271280725-c531b67a-0dad-4385-9f47-8c4e4b2a50ab.png)

可以通过使用这个接口，将一些特殊业务日志存入库中。

使用方法如下：

直接在Bean中注入LogRecordApi即可使用。

```java
@Resource
private LogRecordApi logRecordApi;
```

在类中使用logRecordApi.add()方法即可记录日志

```java
LogRecordDTO logRecordDTO = new LogRecordDTO();
logRecordDTO.setXXX();
logRecordApi.add(logRecordDTO);
```

## 数据库

sys_log

![img](https://cdn.nlark.com/yuque/0/2022/png/25441324/1655271578855-58f7c396-fe29-4708-b209-e6c48decda57.png)

sys_login_log

![img](https://cdn.nlark.com/yuque/0/2022/png/25441324/1655271600144-7aaefce4-1a6b-457a-bd24-d96a66a612fd.png)

## 日志配置

logback-spring.xml

![img](https://cdn.nlark.com/yuque/0/2022/png/25441324/1655271841582-d3b7cedf-94c1-4c55-8131-0702bbb2751b.png)

![img](https://cdn.nlark.com/yuque/0/2022/png/25441324/1655272295742-5b865ddf-ac87-4fc4-8ffa-6261f4cfcf5a.png)

## 项目结构：

log-api：日志模块的api

log-business-login-log：登录日志相关业务

log-business-manage：日志业务模块，包含在线管理日志的业务

log-business-requestapi：日志业务模块，包含对每个api接口的日志记录。

   对控制器层接口的aop操作。

log-sdk-db：日志记录的sdk，用于将日志记录到数据库中，提供相关日志管理接口

log-sdk-file：日志记录的sdk，用于将日志记录到文件中，提供相关日志管理接口

log-spring-boot-starter：日志的spring boot自动加载模块

## 逻辑总结：

log-api：

LogRecordApi：add、addAsync、addBatch——实现在db和file

LogManagerApi：findList、findPage、del、detail——实现在db和file

LoginLogServiceApi：add、loginSuccess、loginFail、loginOutSuccess、loginOutFail——实现在login

constants：LogConstants、LogFileConstants

context：LogRecordContext（*日志操作api的获取*）、ServerInfoContext（*临时缓存服务器信息*）

enums：*日志存储的方式，数据库还是文件*

​	exception：*日志异常*

​	LogConfigExpander：*日志记录相关的配置*

factory：LogRecordFactory（*日志记录创建工厂，用来new LogRecordDTO，并填充一些信息*）

appender：*日志信息追加，用来追加用户的登录信息、http接口请求信息、方法的参数信息*

​	pojo：*日志配置信息、登录日志的dto、登录日志表、日志管理的查询参数、日志记录需要的参数*

threadpool：*异步记录日志用的线程池*

log-business-login-log：常规的MVC结构，SysLoginLogServiceImpl实现了SysLoginLogService, 	      								LoginLogServiceApi两个接口。

log-business-manage：LogManagerController调用LogManagerApi，对应的wrapper包装

log-business-requestapi：与注解挂钩

RequestApiLogRecordAop（*每个请求接口记录日志的AOP*）

*将控制器controller包下的所有控制器类，执行的时候对url，参数，结果等进行记录*

![img](https://cdn.nlark.com/yuque/0/2022/png/25441324/1655627383489-c7029d88-92a1-48be-8723-f030c8929d8c.png)![img](https://cdn.nlark.com/yuque/0/2022/png/25441324/1655627360082-d0c6e732-4b09-4154-adb9-fc1aa41dcb86.png)

1. 1. 判断是否需要记录日志

1. 1. 1. 判断是否需要记录日志，如果不需要直接返回
      2. 获取类上的业务日志开关注解
      3. 获取方法上的业务日志开关注解
      4. 判断开关

1. 1. 获取接口上@PostResource或者@GetResource的name属性和requiredLogin属性
   2. AOP获取参数名称和参数值
   3. 删除Request和Response
   4. 记录日志

1. 1. 1. 创建日志对象
      2. 填充用户登录信息
      3. 填充http接口请求信息
      4. 追加参数信息
      5. 异步记录日志

log-sdk-db：数据库实现LogRecordApi、LogManagerApi功能

log-sdk-file：文件实现LogRecordApi、LogManagerApi功能

DbLogRecordServiceImpl、FileLogRecordServiceImpl：同步直接插入数据库或文件，异步采用线程池和重写线程类，线程类的run方法不断的循环，在循环内数据监听、任务监听。

DbLogManagerServiceImpl、FileLogManagerServiceImpl：就是常规实现日志管理，文件的有点麻烦

log-spring-boot-starter：

GunsLogAutoConfiguration（@Configuration）：自动配置（@Bean）

SysLogServiceImpl、SysLogProperties、RequestApiLogRecordAop、LogManagerApi、LogRecordApi

所以使用的时候就用LogRecordApi来就可以了，默认数据库。

# 文件存储

### 1. 设计目的

更便捷的使用文件管理功能，使用api进行拓展，方便随时切换aliyun，minio，腾讯云，本地存储多种存储模式。

### 2. 封装思想

针对纯文件的操作（不带维护文件元数据）封装在FileOperatorApi接口中。

```java
/**
 * 文件操纵者（内网操作）
 * <p>
 * 如果存在未包含的操作，可以调用getClient()自行获取client进行操作
 *
 * @author fengshuonan
 * @date 2020/10/26 10:33
 */
public interface FileOperatorApi {

    /**
     * 初始化操作的客户端
     *
     * @author fengshuonan
     * @date 2020/10/26 10:33
     */
    void initClient();

    /**
     * 销毁操作的客户端
     *
     * @author fengshuonan
     * @date 2020/10/26 10:33
     */
    void destroyClient();

    /**
     * 获取操作的客户端
     * <p>
     * 例如，获取阿里云的客户端com.aliyun.oss.OSS
     *
     * @author fengshuonan
     * @date 2020/10/26 10:35
     */
    Object getClient();

    /**
     * 查询存储桶是否存在
     * <p>
     * 例如：传入参数exampleBucket-1250000000，返回true代表存在此桶BucketAuthEnum.java
     *
     * @param bucketName 存储桶名称
     * @return boolean true-存在，false-不存在
     * @author fengshuonan
     * @date 2020/10/26 10:36
     */
    boolean doesBucketExist(String bucketName);

    /**
     * 设置预定义策略
     * <p>
     * 预定义策略如公有读、公有读写、私有读
     *
     * @param bucketName     存储桶名称
     * @param bucketAuthEnum 存储桶的权限
     * @author fengshuonan
     * @date 2020/10/26 10:37
     */
    void setBucketAcl(String bucketName, BucketAuthEnum bucketAuthEnum);

    /**
     * 判断是否存在文件
     *
     * @param bucketName 桶名称
     * @param key        唯一标示id，例如a.txt, doc/a.txt
     * @return true-存在文件，false-不存在文件
     * @author fengshuonan
     * @date 2020/10/26 10:38
     */
    boolean isExistingFile(String bucketName, String key);

    /**
     * 存储文件
     *
     * @param bucketName 桶名称
     * @param key        唯一标示id，例如a.txt, doc/a.txt
     * @param bytes      文件字节数组
     * @author fengshuonan
     * @date 2020/10/26 10:39
     */
    void storageFile(String bucketName, String key, byte[] bytes);

    /**
     * 存储文件（存放到指定的bucket里边）
     *
     * @param bucketName  桶名称
     * @param key         唯一标示id，例如a.txt, doc/a.txt
     * @param inputStream 文件流
     * @author fengshuonan
     * @date 2020/10/26 10:39
     */
    void storageFile(String bucketName, String key, InputStream inputStream);

    /**
     * 获取某个bucket下的文件字节
     *
     * @param bucketName 桶名称
     * @param key        唯一标示id，例如a.txt, doc/a.txt
     * @return byte[] 字节数组为文件的字节数组
     * @author fengshuonan
     * @date 2020/10/26 10:39
     */
    byte[] getFileBytes(String bucketName, String key);

    /**
     * 文件访问权限管理
     *
     * @param bucketName     桶名称
     * @param key            唯一标示id，例如a.txt, doc/a.txt
     * @param bucketAuthEnum 文件权限
     * @author fengshuonan
     * @date 2020/10/26 10:40
     */
    void setFileAcl(String bucketName, String key, BucketAuthEnum bucketAuthEnum);

    /**
     * 拷贝文件
     *
     * @param originBucketName 源文件桶
     * @param originFileKey    源文件名称
     * @param newBucketName    新文件桶
     * @param newFileKey       新文件名称
     * @author fengshuonan
     * @date 2020/10/26 10:40
     */
    void copyFile(String originBucketName, String originFileKey, String newBucketName, String newFileKey);

    /**
     * 获取文件的下载地址（带鉴权的），生成外网地址
     *
     * @param bucketName    文件桶
     * @param key           文件唯一标识
     * @param timeoutMillis url失效时间，单位毫秒
     * @return 外部系统可以直接访问的url
     * @author fengshuonan
     * @date 2020/10/26 10:40
     */
    String getFileAuthUrl(String bucketName, String key, Long timeoutMillis);

    /**
     * 删除文件
     *
     * @param bucketName 文件桶
     * @param key        文件唯一标识
     * @author fengshuonan
     * @date 2020/10/26 10:42
     */
    void deleteFile(String bucketName, String key);

}
```

bucket为抽象出的文件桶的概念，也可以作为文件夹，为了区别不同业务的文件存储位置。



其他的带文件元数据维护的功能放在FileInfoApi接口中。

```java
/**
 * 获取文件信息的api
 *
 * @author fengshuonan
 * @date 2020/11/29 16:21
 */
public interface FileInfoApi {

    /**
     * 获取文件详情
     *
     * @param fileId 文件id，在文件信息表的id
     * @return 文件的信息，不包含文件本身的字节信息
     * @author fengshuonan
     * @date 2020/11/29 16:26
     */
    SysFileInfoResponse getFileInfoWithoutContent(Long fileId);

    /**
     * 获取文件的下载地址（带鉴权的），生成外网地址
     *
     * @param fileId 文件id
     * @return 外部系统可以直接访问的url
     * @author fengshuonan
     * @date 2020/10/26 10:40
     */
    String getFileAuthUrl(Long fileId);

    /**
     * 获取文件的下载地址（带鉴权的），生成外网地址
     *
     * @param fileId 文件id
     * @param token  用户的token
     * @return 外部系统可以直接访问的url
     * @author fengshuonan
     * @date 2020/10/26 10:40
     */
    String getFileAuthUrl(Long fileId, String token);

}
```

### 3. 本地存储方式

默认引用file-spring-boot-starter之后，会自动激活本地文件存储方式。

```java
@Configuration
public class GunsFileAutoConfiguration {

    /**
     * 本地文件操作
     *
     * @author fengshuonan
     * @date 2020/12/1 14:40
     */
    @Bean
    @ConditionalOnMissingBean(FileOperatorApi.class)
    public FileOperatorApi fileOperatorApi() {

        LocalFileProperties localFileProperties = new LocalFileProperties();

        // 从系统配置表中读取配置
        localFileProperties.setLocalFileSavePathLinux(FileConfigExpander.getLocalFileSavePathLinux());
        localFileProperties.setLocalFileSavePathWin(FileConfigExpander.getLocalFileSavePathWindows());

        return new LocalFileOperator(localFileProperties);
    }

}
```

使用时，只要在项目注入FileOperatorApi即可进行本地文件操作。

### 4. minio文件存储

如何将默认的文件存储方式替换为minio文件存储? 参考以下步骤。

#### 4.1安装minio

参考https://min.io/download，下载并运行minio

#### 4.2pom配置

在项目的pom.xml中配置minio的依赖。

```xml
<!--minio客户端-->
<dependency>
  <groupId>cn.stylefeng.roses</groupId>
  <artifactId>file-sdk-minio</artifactId>
  <version>${roses.kernel.version}</version>
</dependency>
```

#### 4.3config配置

在Guns项目中排除掉默认的文件配置。

![img](https://cdn.nlark.com/yuque/0/2022/png/25441324/1655709102736-90a069a6-a9f0-4e17-b1d9-225cf0b8f2d1.png)

在config包下，创建新的文件配置，注意服务器路径填写您的信息。

```java
/**
* minio文件配置
*
* @author fengshuonan
* @date 2021/3/30 20:21
*/
@Configuration
public class GunsMinioFileConfiguration {
    
    /**
    * minio文件操作
    *
    * @author fengshuonan
    * @date 2020/12/1 14:40
    */
    @Bean
    @ConditionalOnMissingBean(FileOperatorApi.class)
    public FileOperatorApi fileOperatorApi() {
        
        MinIoProperties minIoProperties = new MinIoProperties();
        
        minIoProperties.setEndpoint("http://127.0.0.1:9000");
        minIoProperties.setAccessKey("accessKey");
        minIoProperties.setSecretKey("secretKey");
        
        return new MinIoFileOperator(minIoProperties);
    }
    
}
```

### 5. 阿里云文件存储

#### 5.1 引入pom配置

在项目的pom.xml中配置aliyun的依赖。

```xml
<!--aliyun oss客户端-->
<dependency>
  <groupId>cn.stylefeng.roses</groupId>
  <artifactId>file-sdk-aliyun</artifactId>
  <version>${roses.kernel.version}</version>
</dependency>
```

#### 5.2 替换自动配置

在Guns项目中排除掉默认的文件配置。

![img](https://cdn.nlark.com/yuque/0/2022/png/25441324/1655709102736-90a069a6-a9f0-4e17-b1d9-225cf0b8f2d1.png)

在config包下，创建新的文件配置，注意服务器路径填写您的信息。

```java
/**
* 阿里云文件配置
*
* @author fengshuonan
* @date 2021/3/30 20:21
*/
@Configuration
public class GunsMinioFileConfiguration {
    
    /**
    * 阿里云文件操作
    *
    * @author fengshuonan
    * @date 2020/12/1 14:40
    */
    @Bean
    @ConditionalOnMissingBean(FileOperatorApi.class)
    public FileOperatorApi fileOperatorApi() {
        
        AliyunOssProperties aliyunOssProperties = new AliyunOssProperties();
        
        aliyunOssProperties.setEndPoint("http://oss-cn-beijing.aliyuncs.com");
        aliyunOssProperties.setAccessKeyId("accessKey");
        aliyunOssProperties.setAccessKeySecret("secretKey");
        
        return new AliyunFileOperator(aliyunOssProperties);
    }
    
}
```

### 6. 腾讯云文件存储

#### 6.1 引入pom配置

在项目的pom.xml中配置tencent的依赖。

```xml
<!--tencent cos客户端-->
<dependency>
  <groupId>cn.stylefeng.roses</groupId>
  <artifactId>file-sdk-tencent</artifactId>
  <version>${roses.kernel.version}</version>
</dependency>
```

#### 6.2 替换自动配置

在Guns项目中排除掉默认的文件配置。

![img](https://cdn.nlark.com/yuque/0/2022/png/25441324/1655709102736-90a069a6-a9f0-4e17-b1d9-225cf0b8f2d1.png)

在config包下，创建新的文件配置，注意服务器路径填写您的信息。

```java
/**
* 腾讯云文件配置
*
* @author fengshuonan
* @date 2021/3/30 20:21
*/
@Configuration
public class GunsMinioFileConfiguration {
    
    /**
    * 腾讯云文件操作
    *
    * @author fengshuonan
    * @date 2020/12/1 14:40
    */
    @Bean
    @ConditionalOnMissingBean(FileOperatorApi.class)
    public FileOperatorApi fileOperatorApi() {
        
        TenCosProperties tenCosProperties = new TenCosProperties();
        
        tenCosProperties.setRegionId("ap-beijing");
        tenCosProperties.setSecretKey("accessKey");
        tenCosProperties.setSecretId("secretKey");
        
        return new TenFileOperator(tenCosProperties);
    }
    
}
```

## 项目结构：

file-api：文件管理api模块

file-business：文件管理模块，可以实现，在线管理和维护文件内容

file-sdk-aliyun：文件模块，阿里云文件的实现

file-sdk-local：文件模块，本地存储文件的实现

file-sdk-minio：文件模块，minio服务器的实现

file-sdk-tencent：文件模块，腾讯云文件的实现

file-spring-boot-starter：文件的spring boot自动加载模块

## 逻辑总结：

FileInfoApi：*获取文件详情、获取文件的下载地址，生成外网地址*

SysFileInfoServiceImpl实现FileInfoApi，（二者都在file-business）

SysFileInfoController：*文件信息管理、包括下载、上传、预览、查询等*

FileOperatorApi：*初始化操作的客户端、销毁操作的客户端、获取操作的客户端、查询存储桶是否存在、设置预定义策略（公有读、公有读写、私有读）、判断是否存在文件、存储文件、获取某个bucket下的文件字节、文件访问权限管理、拷贝文件、获取文件的下载地址（外网地址）、删除文件、获取当前api的文件存储类型。*

​	AliyunFileOperator：private OSS ossClient;*阿里云文件操作客户端*

LocalFileOperator：hutool的FileUtil

MinIoFileOperator：private MinioClient minioClient;*MinIo文件操作客户端*

TenFileOperator：private COSClient cosClient;

GunsFileAutoConfiguration：

​	![img](https://cdn.nlark.com/yuque/0/2022/png/25441324/1655714845510-64776beb-aac1-480f-b3f5-228c7b273672.png)

file-api：FileConstants、FileContext、Enum（*桶的权限策略枚举、文件存储位置、文件状态*）、Exception

FileConfigExpander（*文件相关的配置获取*）、pojo、util（*web文件下载工具封装、pdf文件类型识		别工具*、*文件类型识别工具*）

## 四种方式的选择的：

阿里云和腾讯云是一样的方式，云端存储花钱

本地存储就是放在一个文件夹里面，minio存储利用dokcer建立分布式存储系统，这两个不花钱。

# 系统配置

### 1. 设计目的

统一管理项目中的配置，并可以进行在线修改，实时生效，可以理解为项目中的动态常量。

系统配置全部持久化在表中，并且项目启动时候会加载到缓存，在线修改变量的值可以动态刷新缓存，但是如果手动修改库，则不会动态刷新缓存。

### 2. 如何使用

在Guns中有一个规范，所有系统配置相关的类都以Expander结尾。

在Expander类中，我们常调用的方法是ConfigContext.me().getSysConfigValueWithDefault()或者ConfigContext.me().getConfigValueNullable()

第一个方法获取变量时，如果获取不到则返回一个参数所给的默认值。

第二个方法获取变量时，如果获取不到则返回一个null。

如果项目中有些变量需要我们在项目里进行配置，可以按如下步骤进行使用。

1. 在系统配置中，新建一个系统配置，如下：

![img](https://cdn.nlark.com/yuque/0/2022/png/25441324/1655716933721-d9aec0eb-3637-41a6-93af-c9f1039b829a.png)

1. 编写一个获取我的配置的静态方法：

```java
/**
 * 获取我的自定义配置
 *
 * @author fengshuonan
 * @date 2021/9/23 19:58
 */
public class MyConfigExpander {

    /**
     * 获取我的自定义配置
     *
     * @author fengshuonan
     * @date 2021/9/23 19:58
     */
    public static String getNoneSecurityConfig() {
        return ConfigContext.me().getConfigValueNullable("MY_CONFIG", String.class);
    }

}
```

1. 程序中可以在任意地方调用这个静态方法获取配置值。

```java
@RestController
@ApiResource(name = "获取我的配置")
public class MyConfigController {

    @GetResource(name = "获取我的配置", path = "/myConfig", requiredLogin = false, requiredPermission = false)
    public ResponseData myConfig() {
        return new SuccessResponseData(MyConfigExpander.getMyConfig());
    }

}
```

访问这个接口即可获取到配置的值。并且在线修改值是可以动态刷新的。

为什么可以动态刷新，因为每次都是调用吗。

## 项目结构

kernel-d-config：系统配置表模块

本模块意在建立一块系统配置内存空间，保存一些系统常用的配置，通过在线管理这些配置，可实时维护这	些配置。多模块之间可通过config-api提供的接口，进行配置的共享和读取。在新增一个配置的时候，优先考虑存到config模块，再考虑往application.yml中存。

config-api：配置模块的api模块

config-business：系统配置表在线维护模块，可以在线管理配置

config-sdk-map：系统配置表的实现，基于数据库存储（我感觉用的是缓存）

​	config-sdk-redis：基于Redis的系统配置实现

config-spring-boot-starter：配置模块的spring boot自动加载模块（里面没东西）



ConfigApi：*初始化配置表中的所有配置、获取配置表中所有配置、获取所有配置的名称集合、往配置表中添加一个配置、删除一个配置项、获取config表中的配置。*

ConfigInitCallbackApi：*初始化之前、之后回调。*

ConfigInitStrategyApi：*获取需要被初始化的配置集合。*

SysConfigDataApi：*获取系统配置表中的所有数据、获取所有配置list的sql。*

# 参数校验

### 1. 设计目的

进行请求参数的合法校验，有效打回错误的请求参数。参数校验框架使用的是hibernate validation。

### 2. 快速使用

接口加上请求参数校验，只需两步。

**第一步**在请求参数实体中，加上@NotNull、@NotBlank等注解，用来标识某些参数的输入限制。

例如，如下使用示例：

```java
@Data
public class SysUserRequest extends BaseRequest {

    /**
     * 主键
     */
    @NotNull(message = "userId不能为空")
    private Long userId;

    /**
     * 账号
     */
    @NotBlank(message = "账号不能为空")
    private String account;

}
```

这些注解上一般都有个message参数，这个参数用来参数校验不符合规则时，返回给前端的提示。

常用的校验注解，下面章节会有介绍。

**第二步**在控制器方法的参数上增加@Valid注解即可。

```java
@RestController
@ApiResource(name = "用户管理")
public class SysUserController {

    @Resource
    private SysUserService sysUserService;

    @PostResource(name = "系统用户_注册", path = "/sysUser/register", requiredLogin = false, requiredPermission = false)
    public ResponseData register(@RequestBody @Valid SysUserRequest sysUserRequest) {
        sysUserService.register(sysUserRequest);
        return new SuccessResponseData();
    }
    
}
```

请求接口，如果没有带userId和account参数则会报错：

![img](https://cdn.nlark.com/yuque/0/2022/png/25441324/1655717574648-dddfabc0-944d-49c3-aad5-80560545e60d.png)

### 3. 校验分组

一般一个业务的所有接口，请求参数可能共用一个请求参数。

![img](https://cdn.nlark.com/yuque/0/2022/png/25441324/1655717634396-df906c17-cec1-45a5-acbd-f80bf42d23f0.png)

参数共用，但是每个接口的参数校验规则又不一样，例如新增菜单不需要校验menuId是否传值，修改菜单需要校验menuId是否传值。

这时候就需要校验分组了，将参数实体，增加不同group条件来判断请求需要校验哪些值为空。

**注意：如果需要校验分组，控制器上需要用@Validated，而不是用@Valid**

使用校验分组时，在参数实体中增加group属性即可区分校验分组，在控制器参数上使用@Validated(BaseRequest.add.class)即可。

```java
@Data
public class SysUserRequest extends BaseRequest {

    /**
     * 主键
     */
    @NotNull(message = "userId不能为空", group = { edit.class })
    private Long userId;

    /**
     * 账号
     */
    @NotBlank(message = "账号不能为空", group = { add.class,edit.class })
    private String account;

}
@RestController
@ApiResource(name = "用户管理")
public class SysUserController {

    @Resource
    private SysUserService sysUserService;

    @PostResource(name = "系统用户_增加", path = "/sysUser/add")
    public ResponseData add(@RequestBody @Validated(BaseRequest.add.class) SysUserRequest sysUserRequest) {
        sysUserService.add(sysUserRequest);
        return new SuccessResponseData();
    }
    
}
```

### 4. 常用注解

| **注解名称**               | **功能**                                                     |
| -------------------------- | ------------------------------------------------------------ |
| @Null                      | 检查该字段为空                                               |
| @NotNull                   | 不能为null                                                   |
| @NotBlank                  | 不能为空，常用于检查空字符串                                 |
| @NotEmpty                  | 不能为空，多用于检测list是否size是0                          |
| @Max                       | 该字段的值只能小于或等于该值                                 |
| @Min                       | 该字段的值只能大于或等于该值                                 |
| @Past                      | 检查该字段的日期是在过去                                     |
| @Future                    | 检查该字段的日期是否是属于将来的日期                         |
| @Email                     | 检查是否是一个有效的email地址                                |
| @Pattern(regex=,flag=)     | 被注释的元素必须符合指定的正则表达式                         |
| @Range(min=,max=,message=) | 被注释的元素必须在合适的范围内                               |
| @Size(min=, max=)          | 检查该字段的size是否在min和max之间，可以是字符串、数组、集合、Map等 |
| @Length(min=,max=)         | 检查所属的字段的长度是否在min和max之间,只能用于字符串        |
| @AssertTrue                | 用于boolean字段，该字段只能为true                            |
| @AssertFalse               | 该字段的值只能为false                                        |

### 5. 自定义校验注解

如需定制自定义的校验注解，可以参考validator-api模块下的注解的写法，实现自定义校验的功能，只需编写两个类即可。

![img](https://cdn.nlark.com/yuque/0/2022/png/25441324/1655717896730-c9523d09-daa7-4de5-ba49-bd17f2383ae1.png)

![img](https://cdn.nlark.com/yuque/0/2022/png/25441324/1655725191822-5f3d3e55-8e04-4646-8efc-53690418fa63.png)

### 6. @TableUniqueValue注解

这个注解使用的比较多，一般用在单个表中某个字段的值不能存在重复的校验。

例如，应用管理，添加应用的时候，应用编码需要校验全表唯一，不能存在重复，就可以用这个注解实现。

使用方法也很简单，在请求参数pojo中，加上@TableUniqueValue注解即可。

![img](https://cdn.nlark.com/yuque/0/2022/png/25441324/1655725276284-46b108ef-f907-4d24-8f62-5f454842dad1.png)

message：响应前端的错误提示

groups: 参数校验分组

tableName： 被校验的表的名称

columnName： 被校验的字段名称

idFieldName： 当前表的主键id字段，这个参数设置是为了在编辑时候，排除当前记录

excludeLogicDeleteItems： 校验时是否排除逻辑删除的内容

## 项目结构

kernel-d-validator：参数校验模块

validator-api：配置模块的api模块

validator-api-table-unique：将@TableUniqueValue注解的校验单独提出来

validator-spring-boot-starter：校验器的spring boot自动加载模块

分组、自定义校验。

validator-spring-boot-starter：

CacheParamRequestBodyAdvice：使用线程池RequestParamContext进行缓存。

GunsValidator：*用于真正校验参数之前缓存一下group的class类型（线程池*RequestGroupContext*）*

GunsValidatorAutoConfiguration：*自定义的**spring**参数校验器，重写主要为了保存一些在自定义**validator**中读不到的属性*

validator-api：constants、context（线程池）、异常、pojo、validators（date、flag、phone、status）

# Wrapper包装

### 1. 设计目的

提供一种更灵活的响应结果包装方式。在Wrapper中，可以更灵活的运用缓存等，加快接口响应速度。

举个例子：

在分页查询定时任务接口中，原本接口返回SysTimers这个实体的List，SysTimers实体中没用用户的姓名，但是只有用户id。

![img](https://cdn.nlark.com/yuque/0/2022/png/25441324/1655883168286-e68354d5-723d-45b0-bfef-3ff0a2e39802.png)

但是，定时任务列表界面上，要展示创建人的姓名，

![img](https://cdn.nlark.com/yuque/0/2022/png/25441324/1655883196109-28e89bf3-876a-4c32-88af-c2db7f05450e.png)

**第一种解决办法**就是修改查询语句，将原本的单表查询改为和sys_user表联查，得到用户姓名。

**第二种解决办法**就是使用Wrapper。在控制器方法上，增加一个@Wrapper(TimerWrapper.class)，并且编写TimerWrapper类如下。

![img](https://cdn.nlark.com/yuque/0/2022/png/25441324/1655883285351-a3d3a321-3176-4519-bfea-2e5cc247beac.png)

这样就可以将创建人姓名展示出来，既节省了mysql的开销，也加快了接口响应速度（因为getUserInfoByUserId用了缓存）。

### 2. 使用方法

正如上节所介绍，使用时候，只需加注解并且编写Wrapper类即可。下面介绍下Wrapper类的具体组成。

编写Wrapper类注意三点。

第一点是需要实现BaseWrapper接口，并且接口带泛型。

第二点是doWrap参数，参数需要是控制器上ResponseData内容的实体，满足各种位置的包装。

第三点是返回值，返回值是针对原有实体的一个增量的Map。

![img](https://cdn.nlark.com/yuque/0/2022/png/25441324/1655884132943-e1d35d9b-1160-4298-8c2b-53a16e42653e.png)

### 3. 核心原理

其实Map + Wrapper的原理是利用aop，将结果进行二次包装。

核心逻辑可以看cn.stylefeng.roses.kernel.wrapper.WrapperAop这个类。

## 项目结构

wrapper-api：@Wrapper（*结果包装的注解，一般用在Controller层，给最后响应结果做包装*）

   BaseWrapper（*基础包装接口*）——doWrap（*基础包装接口*）

wrapper-sdk：WrapperAop——配置到bean中，扫描到注解便对输出的类型进行修改。

wrapper-spring-boot-starter：

GunsWrapperAutoConfiguration：WrapperAop

# 微服务

因为要给桌面端提供服务，所以黄总考虑要设置微服务。

当项目的压力过大，可以考虑将项目的功能拆分，分别部署维护，服务之间通过http、rpc进行调用。

多模块可以war、jar部署

只要把有接口的模块都引入到主模块就好了，就可以打成jar包了。

war包的部署

先打成war包，war包就是一个web服务，然后放入tomcat文件夹的webapps中，在bin中启动tomcat。

什么时候要升级为微服务

高并发、数据量大（多数据源）、涉及大量分布式（缓存、事务、锁），服务集群超过3个

## 服务区分

用若依举例：

#### 单模块应用：[RuoYi-fast](https://gitee.com/y_project/RuoYi-fast)——容易维护（SpringBoot+Bootstrap）

#### 前后端不分离：[RuoYi](https://gitee.com/y_project/RuoYi)（SpringBoot+Bootstrap）

#### 前后端分离：[RuoYi-Vue](https://gitee.com/y_project/RuoYi-Vue)（SpringBoot+Vue）

#### 微服务项目：[RuoYi-Cloud](https://gitee.com/y_project/RuoYi-Cloud)——加上了网关、把modules分开，服务注册、服务发现等等（SpringCloud+Vue）每个模块设定不同的端口，通过网关进行映射。

## 前后端分离部署问题

https://blog.51cto.com/YangRoc/5084293

# 缓存

### 1. 设计目的

使用缓存大大提高业务的查询效率。缓存一般加在查询业务上，同时要注意修改了业务数据之后要清空对应的缓存。

### 2. 基于接口

缓存模块的设计师基于接口的，最顶层的CacheOperatorApi接口，然后有AbstractMemoryCacheOperator和AbstractRedisCacheOperator两个抽象类，分别是基于内存的缓存和基于Redis的缓存的基类。

### 3. 如何使用

1. 项目中引用缓存地starter，如果使用内存的只引用上边的就可以，如果使用redis缓存，则需要引用下边的

```xml
<!--内存的缓存-->
<dependency>
  <groupId>cn.stylefeng.roses</groupId>
  <artifactId>memory-cache-spring-boot-starter</artifactId>
  <version>${roses.kernel.version}</version>
</dependency>

<!--Redis的缓存-->
<dependency>
  <groupId>cn.stylefeng.roses</groupId>
  <artifactId>redis-spring-boot-starter</artifactId>
  <version>${roses.kernel.version}</version>
</dependency>
```

1. 如果是redis的缓存，需要项目中进行相关redis连接的配置：

![img](https://cdn.nlark.com/yuque/0/2022/png/25441324/1655860056832-fbdddd45-2e4c-470f-8e7a-6e4b79236663.png)

1. 编写缓存类：

```java
/**
* 例如，这是基于内存缓存的
*
* @author fengshuonan
* @date 2021/9/22 23:08
*/
public class MemoryCarCache extends AbstractMemoryCacheOperator<Car> {
    
    public MemoryCarCache(TimedCache<String, Car> timedCache) {
        super(timedCache);
    }
    
    @Override
    public String getCommonKeyPrefix() {
        return "CAR_CACHE:";
    }
    
}
/**
* 例如，这是基于Redis缓存的
*
* @author fengshuonan
* @date 2021/9/22 23:09
*/
public class RedisCarCache extends AbstractRedisCacheOperator<Car> {
    
    public RedisCarCache(RedisTemplate<String, Car> redisTemplate) {
        super(redisTemplate);
    }
    
    @Override
    public String getCommonKeyPrefix() {
        return "CAR_CACHE:";
    }
    
}
```

1. 装配缓存类到spring容器中。

```java
/**
 * 基于内存的车辆缓存
 *
 * @author fengshuonan
 * @date 2021/9/22 23:24
 */
@Bean
public MemoryCarCache carCache() {
    TimedCache<String, Car> carTimedCache = CacheUtil.newTimedCache(1000L * 60);
    return new MemoryCarCache(carTimedCache);
}
```

如果是Redis的需要进行如下装配：

```java
/**
 * 基于redis的车辆缓存
 *
 * @author fengshuonan
 * @date 2021/9/22 23:24
 */
@Bean
public RedisCarCache carCache(RedisConnectionFactory redisConnectionFactory) {
    RedisTemplate<String, Car> object = CreateRedisTemplateUtil.createObject(redisConnectionFactory);
    return new RedisCarCache(object);
}
```

1. 之后就可以注入CacheOperatorApi进行使用缓存了，如下使用用例。

```java
// 先从缓存中获取
if (StrUtil.isEmpty(carRequest.getCarName())) {
    Collection<Car> allCars = carCache.getAllValues();
    if (ObjectUtil.isNotEmpty(allCars)) {
        return new ArrayList<>(allCars);
    }
}

LambdaQueryWrapper<Car> wrapper = this.createWrapper(carRequest);
List<Car> list = this.list(wrapper);

// 将查询结果插入到缓存
if (StrUtil.isEmpty(carRequest.getCarName()) && ObjectUtil.isNotEmpty(list)) {
    for (Car car : list) {
        carCache.put(String.valueOf(car.getCarId()), car);
    }
}

return list;
```

## 项目结构——缓存模块

cache-api：缓存模块，提供一些缓存接口。缓存模块为了给系统提供缓存功能，更快的执行业务

CacheOperatorApi：*缓存操作的基础接口，可以实现不同种缓存实现*

cache-sdk-memory：系统配置表的实现，基于数据库存储

AbstractMemoryCacheOperator：*基于内存的缓存封装*——HuTool：TimedCache

​		DefaultMemoryCacheOperator、DefaultStringMemoryCacheOperator

cache-sdk-redis：系统配置表的实现，基于redis存储

AbstractRedisCacheOperator：*基于redis的缓存封装*——RedisTemplate

DefaultRedisCacheOperator、DefaultStringRedisCacheOperator

memory-cache-spring-boot-starter：内存缓存的默认配置

GunsMemoryCacheAutoConfiguration：*创建默认的value是string、object类型的内存缓存*

redis-spring-boot-starter：redis缓存的默认配置
	GunsRedisCacheAutoConfiguration：*Redis的value序列化器、value是object、string类型的redis操作类、创建默认的value是string、object类型的redis缓存。*

*自动配置*

*@bean出来的类，应该一个*@Resource就能调出来，这样才叫声明放入bean容器中。

剩下的类，都是通过一层层的pom，引入过来的，所以都能调过来。bean的好处就是，类不需要新new出来了，在配置类中new过，放在了bean容器中，直接调用就好了，可以映射过来。所有类都能调过来，需要的也可以自己配置。

## 二者选择

分别是内存实现（Hutool）和redis实现

在单项目部署中，内存还是很好使的，如果多个集群，内存实现就不是那么适合了。

本地缓存用于提高响应速度，但不同服务器中分别有自己的本地缓存，考虑本地找不到，就去查远程redis缓存，redis缓存有集群设置，可以在整个项目维护一个缓存，再找不到再去查mysql。所以在项目需要集群的情况下，要整合redis，单服务器的话，本地缓存感觉就够了。

https://blog.csdn.net/qq_41013833/article/details/120214669

还要考虑负载均衡，接口映射的特点，如果一个用户一直请求一个服务器，那本地缓存肯定就没啥问题。

目前还是先考虑单体架构，单台服务器部署，本地缓存。

如果要分布式部署，就舍弃本地缓存，采用redis。

分布式场景：就是多个节点构成集群的项目。

分布式缓存：通过网络和项目沟通，缓存自己搭建集群，保持数据一致性。



# 多数据源

datasource-container

每一个租户就是一个新的数据源，多数据源可以访问多个不同的数据库

使用场景：

**业务复杂（数据量大）**

数据分布在不同的数据库中，数据库拆了， 应用没拆。 一个公司多个子项目，各用各的数据库，涉及数据共享…

**读写分离**

这种我觉得离谱，还是要搭建读写分离的基础设施的，总不能让开发人员自行读写分离。

目前还没有这种压力，多数据源仅仅用在租户上。

### 1. 在线配置

通过多数据源菜单可以在线添加数据源。

![img](https://cdn.nlark.com/yuque/0/2022/png/25441324/1655824247364-e624188f-4f0c-4415-8b13-d22bfaafba71.png)

### 2. 使用多数据源

只需在代码的service层，加上@DataSource注解即可，注意name要和数据库录入时候的名称一致。

```java
@Service
public class OtherDbService extends ServiceImpl<SysUserMapper, SysUser> {

    @Resource
    private SysUserService sysUserService;

    @DataSource(name = "mydatasource")
    public void otherDb() {
        sysUserService.save(NormalUserFactory.createAnUser());
    }

}
```

### 3. 手动切换

如果程序汇总某个地方要手动切换一下数据源，可以用如下方法实现：

```java
// 获取当前上下文的数据源名称
String dataSourceName = CurrentDataSourceContext.getDataSourceName();
try {
    // 做你需要做的操作
} finally {
    // 切换回去数据源
    CurrentDataSourceContext.setDataSourceName(dataSourceName);
}
```

## 项目结构

ds-container-api：

@DataSource

CurrentDataSourceContext使用线程池，来记录目前所使用的数据源。

ds-container-business：数据源容器的业务模块，在线维护数据源信息

ds-container-sdk：

MultiSourceExchangeAop实现@DataSource逻辑

ds-container-spring-boot-starter：多数据源的spring boot自动加载模块

DynamicDataSource：*多数据源连接池*

MultiSourceExchangeAop：*数据源切换的AOP*

# 支付

## 接入支付宝支付

### application.yml添加支付宝支付appid等信息

```yaml
alipay:
  appId: 2021000117660206
  gatewayHost: openapi.alipaydev.com
  notifyUrl: http://101.132.1.2:8001/pay/notify_url
  merchantPrivateKey: MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC+g1/v3Z968
  alipayPublicKey: MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
```

注：openapi.alipaydev.com 是沙盒环境 ，正式环境需要更换网关

gatewayHost：必须是外网穿透host，否则阿里无法回调成功

### 使用Demo

```java
package com.alipay.controller;

import cn.hutool.core.lang.UUID;
import cn.stylefeng.roses.kernel.pay.api.PayApi;
import cn.stylefeng.roses.kernel.pay.api.pojo.TradeRefundResponse;
import com.alipay.easysdk.factory.Factory;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;

/**
* 支付模块测试
*
* @author huziyang
* @date 2021/05/29 21:38
*/
@RestController
@RequestMapping("/test")
@Slf4j
public class AlipayTest {
    
    
    @Resource
    private PayApi payApi;
    
    /**
    * PC支付
    *
    * @return 支付页面
    * @author huziyang
    * @date 2021/04/20 20:43
    */
    @GetMapping("/page")
    public String page(){
        return payApi.page("xx全屋定制", "eb58cd5c-7613-41ce-93ef-fcf0ad4284f9","12.5",null);
    }
    
    /**
    * 手机支付
    *
    * @return 支付页面
    * @author huziyang
    * @date 2021/04/20 20:43
    */
    @GetMapping("/wap")
    public String wap(){
        return payApi.wap("xx全屋定制", "eb58cd5c-7613-41ce-93ef-fcf0ad4284f8","12.5",null,null);
    }
    
    /**
    * 退款
    * 
    * @return 退款实体
    * @author huziyang
    * @date 2021/04/20 20:43
    */
    @PostMapping("/refund")
    public TradeRefundResponse refund() {
        return payApi.refund("eb58cd5c-7613-41ce-93ef-fcf0ad4284f8", "12.5");
    }
    
    
    /**
    * 支付宝回调
    *
    * @param request
    * @throws Exception
    * @author huziyang
    * @date 2021/04/20 20:43
    */
    @PostMapping("/notify_url")
    public void notify(HttpServletRequest request) throws Exception {
        if (request.getParameter("trade_status").equals("TRADE_SUCCESS")) {
            Map<String, String> params = new HashMap<>();
            Map<String, String[]> requestParams = request.getParameterMap();
            for (String name : requestParams.keySet()) {
                params.put(name, request.getParameter(name));
            }
            if (Factory.Payment.Common().verifyNotify(params)) {
                log.info("支付宝异步回调成功");
                log.info("订单名称: " + params.get("subject"));
                log.info("交易状态: " + params.get("trade_status"));
                log.info("支付宝交易凭证号: " + params.get("trade_no"));
                log.info("商家订单号: " + params.get("out_trade_no"));
                log.info("交易金额: " + params.get("total_amount"));
                log.info("支付宝唯一id: " + params.get("buyer_id"));
                log.info("付款时间: " + params.get("gmt_payment"));
                log.info("付款金额: " + params.get("buyer_pay_amount"));
            }
        }
    }
}
```

### pom中引用支付依赖

```xml
<dependency>
  <groupId>cn.stylefeng.roses</groupId>
  <artifactId>pay-spring-boot-starter</artifactId>
  <version>${roses.version}</version>
</dependency>
```

至此支付宝支付就接入成功啦！

如果需要配置应用公钥证书文件路径等信息，参照如下yml（具体配置参数可以查看支付宝支付官方文档）

```yaml
alipay:
  appId:
  gatewayHost:
  notifyUrl:
  merchantPrivateKey:
  alipayPublicKey:
  encryptKey:
  merchantCertPath:
  alipayCertPath:
  alipayRootCertPath:
```

## 项目结构

pay-api：PayConstants、PayException、TradeRefundResponse（*退款响应*）

PayApi：*PC网页支付、手机支付、退款*

pay-sdk-alipay：AlipayConfig（*阿里支付配置类*）

​	AlipayServiceImpl：*阿里支付接口实现*

pay-spring-boot-starter：

GunsPayAutoConfiguration：AlipayServiceImpl（*支付 阿里支付实现*）



## 微信小程序支付

https://blog.csdn.net/qq_32340877/article/details/111595124

### 官方文档

https://developers.weixin.qq.com/miniprogram/dev/wxcloud/guide/wechatpay/wechatpay.html

支付宝支付可能更好，有沙箱环境模拟支付后期改下参数就可以

### 第二种，后端介入的方式

https://pay.weixin.qq.com/wiki/doc/apiv3/open/pay/chapter2_8_0.shtml

https://pay.weixin.qq.com/wiki/doc/api/wxa/wxa_api.php?chapter=7_11&index=2

https://blog.csdn.net/qq_41432730/article/details/124061013

# mysql集群

https://blog.csdn.net/weixin_40612128/article/details/121430739

# redis集群

## DB和Flyway

### 1. Mybatis-Plus的拓展

CustomDatabaseIdProvider： 根据不同数据库类型，进行sql切换的配置。

CustomMetaObjectHandler： 字段自动填充工具，在mybatis-plus执行更新和新增操作时候，会对指定字段进行自动填充，例如 create_time 等字段

### 2. Flyway相关

项目中默认集成了Flyway，Flyway的作用是进行数据库脚本管理，方便针对数据库的升级。

FlywayInitListener类会在项目启动之前执行，它会去检查项目中db.migration.mysql文件夹中的数据库脚本，如果文件夹中有未初始化的脚本则会自动去执行更新。

当然，如果脚本内容和真实数据库有差距，可能会执行失败，导致项目启动不起来。

**这时候有两种解决办法，第一种是直接把库里的表全部删除，程序会自动再进行初始化为对的数据库表。**

**第二种是关掉flyway的开关，开发人员手动处理错误的数据。**

如何关闭flyway，只需在application.yml中关闭flyway开关即可，如下：

![img](https://cdn.nlark.com/yuque/0/2022/png/25441324/1658036834886-6303ba5b-a40f-493d-b240-8a721955fe6e.png)

### 3. Druid相关配置

GunsDruidMonitorAutoConfiguration类中，配置了Druid数据监控的相关配置，其中包括了Druid控制台界面的账号密码，Druid的监控规则等。

如需修改Druid控制台的登录账号和密码，只需要在系统配置表中搜索druid的相关配置即可。

![img](https://cdn.nlark.com/yuque/0/2022/png/25441324/1658037457216-31332c55-cdd1-4204-8fb2-4bed35775382.png)

## 邮件插件

### 1. java mail

1. pom中引用email-spring-boot-starter模块

```xml
<!--邮件发送-->
<dependency>
  <groupId>cn.stylefeng.roses</groupId>
  <artifactId>email-spring-boot-starter</artifactId>
  <version>${roses.kernel.version}</version>
</dependency>
```

1. 在线进行java邮件的相关配置

![img](https://cdn.nlark.com/yuque/0/2022/png/25441324/1658042885606-d1bb7205-bad6-42ba-9720-8eaa197dbdbc.png)

1. 使用MailSenderApi接口，发送邮件即可

```java
@Resource
private MailSenderApi mailSenderApi;

// ...省略
mailSenderApi.sendMailHtml(regEmailParam);
```

### 2. 阿里云邮件

1. 引用阿里云的相关pom

```xml
<dependency>
  <groupId>cn.stylefeng.roses</groupId>
  <artifactId>email-sdk-aliyun</artifactId>
  <version>${roses.kernel.version}</version>
</dependency>
```

1. 项目中进行对阿里云的邮件发送接口进行配置

```java
/**
* 阿里云邮件配置
*
* @author fengshuonan
* @date 2021/9/23 21:02
*/
@Configuration
public class AliyunMailConfiguration {
    
    @Bean
    public MailSenderApi mailSenderApi() {
        AliyunMailSenderProperties aliyunMailSenderProperties = new AliyunMailSenderProperties();
        aliyunMailSenderProperties.setAccessKeyId("");
        aliyunMailSenderProperties.setAccessKeySecret("");
        aliyunMailSenderProperties.setAccountName("");
        return new AliyunMailSender(aliyunMailSenderProperties);
    }
    
}
```

1. 使用AliyunMailSender，发送邮件即可

```java
@Resource
private AliyunMailSender mailSenderApi;
    
// ...省略
mailSenderApi.sendAliyunMail(regEmailParam);
```

## Groovy插件

使用Groovy可以让程序动态执行一些java代码，在某些时候可以不用重启项目，进行一些动态的业务控制。

使用时，只需程序引用groovy-spring-boot-starter模块，并且注入GroovyApi接口，即可调用内部的方法。

```java
public static void main(String[] args){
    GroovyOperator groovyOperator = new GroovyOperator();
    groovyOperator.executeShell("System.out.println(\"123\");");
}
```

## 拼音插件

### 1. 设计目的

封装拼音相关工具方法，可将中文文字转化成拼音全拼，拼音首字母等。

### 2. 功能介绍

拼音相关的转化使用的是pinyin4j。相关方法封装在PinYinApi。

使用时只需注入PinYinApi到service类中即可。

![img](https://cdn.nlark.com/yuque/0/2022/png/25441324/1658043650749-2de4e1f6-0024-447f-97a4-dd91ca260269.png)

拼音相关方法如下：

```java
/**
 * 拼音转化接口
 *
 * @author fengshuonan
 * @date 2020/12/4 9:30
 */
public interface PinYinApi {

    /**
     * 获取姓氏的首字母大写
     * <p>
     * 百家姓涉及到多音字的，都配置在properties中，优先读取properties中的映射
     * <p>
     * 例如：张 -> Z
     * 例如：单 -> S
     *
     * @param lastnameChines 中文姓氏
     * @return 姓氏的首字母大写
     * @author fengshuonan
     * @date 2020/12/4 10:34
     */
    String getLastnameFirstLetterUpper(String lastnameChines);

    /**
     * 将文字转为汉语拼音，取每个字的第一个字母大写
     * <p>
     * 例如：你好 => NH
     *
     * @param chineseString 中文字符串
     * @return 中文字符串每个字的第一个字母大写
     * @author fengshuonan
     * @date 2020/12/4 13:41
     */
    String getChineseStringFirstLetterUpper(String chineseString);

    /**
     * 获取汉字字符串的全拼拼音
     * <p>
     * 例如：中国人 -> zhongguoren
     *
     * @param chineseString 中文字符串
     * @return 拼音形式的字符串
     * @author fengshuonan
     * @date 2020/12/4 14:55
     */
    String parsePinyinString(String chineseString);

    /**
     * 将中文字符串转化为汉语拼音，取每个字的首字母
     * <p>
     * 例如：中国人 -> zgr
     *
     * @param chinesString 中文字符串
     * @return 每个字的拼音首字母组合
     * @author fengshuonan
     * @date 2020/12/4 15:18
     */
    String parseEveryPinyinFirstLetter(String chinesString);

    /**
     * 将中文字符串转移为ASCII码
     *
     * @param chineseString 中文字符串
     * @return ASCII码
     * @author fengshuonan
     * @date 2020/12/4 15:21
     */
    String getChineseAscii(String chineseString);

}
```

## 短信插件

### 1. 设计目的

集成腾讯云短信，阿里云短信，并且以接口实现，可拓展其他云服务商短信。

### 2. 模块介绍

api接口模块给项目或其他模块使用，直接注入api就可以直接发短信。

sdk-aliyun集成了阿里云短信的短信发送实现。

sdk-tencent集成了腾讯云的短信发送实现。

business-validation是带短信验证码校验功能的业务模块，同时，业务模块引用了sdk模块。

![img](https://cdn.nlark.com/yuque/0/2022/png/25441324/1658044761658-23986250-c6c3-4c10-93e8-e36e15275bf7.png)

sms-spring-boot-starter模块包含一个自动配置类。默认提供了阿里云的短信服务集成。

![img](https://cdn.nlark.com/yuque/0/2022/png/25441324/1658044870667-839e01c3-ab25-4d1a-b39c-42b90e8dbaed.png)

### 3. 使用阿里云短信

如果使用阿里云短信。则直接在项目引用sms-spring-boot-starter模块即可。

```xml
<!--短信模块-->
<dependency>
  <groupId>cn.stylefeng.roses</groupId>
  <artifactId>sms-spring-boot-starter</artifactId>
  <version>${roses.kernel.version}</version>
</dependency>
```

然后在系统的系统配置页面，配置上阿里云的相关秘钥即可使用。

发送短信的话，在类中注入SmsSenderApi，即可调用sendSms()方法。

![img](https://cdn.nlark.com/yuque/0/2022/png/25441324/1658045007565-9c6d0b36-79f3-4716-87ac-ac49f6b49bfb.png)

![img](https://cdn.nlark.com/yuque/0/2022/png/25441324/1658045013573-74124236-8ebc-48aa-859f-cec04901360c.png)

### 4. 使用腾讯云短信

在项目中引用腾讯云的sdk。

```xml
<!--短信模块-->
<dependency>
    <groupId>cn.stylefeng.roses</groupId>
    <artifactId>sms-sdk-tencent</artifactId>
    <version>${roses.kernel.version}</version>
</dependency>
```

编写一个配置类，装配SmsSenderApi到项目，配置时注意填写正确的secretKey和secretId等。

```java
@Configuration
public class TencentSmsConfiguration {
    
    @Bean
    public SmsSenderApi smsSenderApi() {
        
        TencentSmsProperties tencentSmsProperties = new TencentSmsProperties();
        
        // 配置默认从系统配置表读取
        tencentSmsProperties.setSdkAppId("");
        tencentSmsProperties.setSecretKey("");
        tencentSmsProperties.setSecretId("");
        tencentSmsProperties.setSign("");
        
        return new TencentSmsSender(tencentSmsProperties);
    }
    
}
```

发送短信的话，在类中注入SmsSenderApi，即可调用sendSms()方法。

![img](https://cdn.nlark.com/yuque/0/2022/png/25441324/1658045220621-bdd125dc-5db6-43e5-801e-4e96c2e8917d.png)

## 定时任务

### 1. 设计目的

提供一种简单的单体服务的定时任务，实现一个简单接口即可编写定时任务类，并且可在线管理定时任务。

### 2. 编写定时任务类

所有的定时任务，都是一个类，并且必须实现cn.stylefeng.roses.kernel.timer.api.TimerAction这个接口，并装配到spring容器中。

下面这个就是一个简单的定时任务。

```java
/**
 * 这是一个定时任务的示例程序
 *
 * @author stylefeng
 * @date 2020/6/30 22:09
 */
@Component
public class SystemOutTaskRunner implements TimerAction {

    @Override
    public void action(String params) {
        System.out.println(StrUtil.format("这是一个定时任务测试的程序，一直输出这行内容！这个是参数: {}", params));
    }

}
```

### 3. 在线创建定时任务调度

打开管理系统，系统功能->定时任务菜单，可以在线创建定时任务。

![img](https://cdn.nlark.com/yuque/0/2022/png/25441324/1658045445816-14859983-609f-46a0-a362-acbf3bc70e85.png)

创建之后，点击启动，如下，即可启动定时任务。

![img](https://cdn.nlark.com/yuque/0/2022/png/25441324/1658045562565-99b0c37d-fc71-4b8c-99e0-47570a458c98.png)

启动之后可以看到控制台一直输出一行字，说明定时任务生效。

![img](https://cdn.nlark.com/yuque/0/2022/png/25441324/1658045583313-90296e56-8641-42b2-ae2e-6f29e03b3614.png)

### 4. cron表达式

cron表达式可以在线生成。使用如下网站：

https://cron.qqe2.com/

## C端业务

C端指Customer，针对移动端、app、小程序等系统。C端业务一般包含了注册、激活、登录、找回密码等操作。

C端业务默认已经包含在Guns项目中。

![img](https://cdn.nlark.com/yuque/0/2022/png/25441324/1658046635912-28aa40d7-d2cb-4b57-9cba-630dd9401405.png)

## 演示环境

演示环境用在Guns的演示环境中，演示环境的原理是使用sql拦截器，只通过select查询，不通过update和delete等操作。

演示环境的核心拦截器在DemoProfileSqlInterceptor。

通过在sys_config表中的配置SYS_DEMO_ENV_FLAG，可以控制演示环境是否打开。

## 字典业务

字典业务包含了字典数据的管理，字典业务分为两张表。

第一个是sys_dict_type表，如下表所示：

![img](https://cdn.nlark.com/yuque/0/2022/png/25441324/1658046763801-fecdc8b0-1641-4e74-8c40-0cbb351c0f0e.png)

第二个是sys_dict表，如下表所示：

![img](https://cdn.nlark.com/yuque/0/2022/png/25441324/1658046782557-334b700d-0605-445c-b5e4-76bfe7af391e.png)

## 编写拓展插件

插件的本质是maven模块，编写一个单独插件和Roses中的各个模块区别不大。

编写插件过程中注意如下几点：

1. 可按api,business,starter这样的格式创建三个模块。
2. pom中的名字要和文件夹名字一致。
3. api中放常量，枚举，异常，pojo，以及api接口。
4. business中放业务，controller，mapper，entity，service等。
5. starter中放一些spring集成需要的配置。

## 微服务插件

### 1. 插件参数

| **插件属性** | **说明**      |
| ------------ | ------------- |
| 适用Guns版本 | Guns v7最新版 |
| 官方认证     | √             |
| 测试通过     | √             |
| 提供文档     | √             |
| v7同步更新   | √             |

### 2. 使用技术栈

- Spring Cloud
- Spring Cloud Alibaba
- Spring Cloud Gateway
- Nacos
- Sentinel
- Openfeign
- Spring Cloud Loadbalancer

**以上组件均使用最新稳定版**

**微服务版本前端采用Guns Vue插件**

演示地址同vue前端插件：

http://vue3.javaguns.com/ 账号：admin 密码：123456

### 3. 微服务实现功能

#### 1.注册中心

注册中心集成了阿里开源的Nacos，功能丰富，包含服务注册，配置管理，动态 DNS 服务，元数据管理等。

Nacos支持健康检查，多种负载均衡策略，支持百万级并发，可以无缝集成spring cloud。

![img](https://cdn.nlark.com/yuque/0/2022/png/25441324/1658057663260-5da13213-f67c-4cb7-b118-d43a64cd2567.png)

#### 2.微服务网关

网关集成了Spring Cloud Gateway网关，可动态配置路由转发规则，并实现了权限和认证等相关过滤器。

网关集成了Nacos注册中，接收到的请求可智能路由到service业务微服务上。

#### 3.熔断降级

熔断降级采用的阿里开源的Sentinel，对调用链不稳定的资源进行熔断降级是保障高可用的重要措施之一。

![img](https://cdn.nlark.com/yuque/0/2022/png/25441324/1658057681494-cfe3fbbc-520a-48d1-9f45-7c062dca65a5.png)

#### 4.限流

Sentinel提供了丰富的限流、熔断功能。它支持控制台配置限流、熔断规则，支持集群限流，并可以将相应服务调用情况可视化。

![img](https://cdn.nlark.com/yuque/0/2022/png/25441324/1658057743976-9cba216a-ae6f-4e0d-82f8-fd533b5fa481.png)

#### 5.客户端负载均衡

客户端负载均衡使用了spring cloud loadbalancer组件。spring cloud loadbalancer会读取注册中心中service实例列表，对远程调用的服务按注册中心分配的权重进行路由。

#### 6.消息队列

框架采用Apache RocketMQ，构建的低延迟、高并发、高可用、高可靠的分布式消息中间件。

#### 7.分布式事务

框架提供两种微服务事务解决方案，第一种采用可靠消息最终一致性解决。第二种采用阿里开源的Seata框架解决。

#### 8.分布式锁

框架提供基于Redis实现的分布式锁，底层使用SETNX实现原子操作。

#### 9.服务监控

使用spring boot admin监控spring cloud各个微服务生命周期，针对健康状况，jvm信息，日志版本管理，class管理等进行有效管理。

![img](https://cdn.nlark.com/yuque/0/2022/png/25441324/1658058286912-7427efe2-6346-491a-aed6-188c9bd4b658.png)

![img](https://cdn.nlark.com/yuque/0/2022/png/25441324/1658058291124-2271eccf-2cdd-412a-bf64-afc19c5e5ed6.png)

## SSO单点登录

### 1. 插件参数

| **插件属性** | **说明**      |
| ------------ | ------------- |
| 适用Guns版本 | Guns v7最新版 |
| 官方认证     | √             |
| 测试通过     | √             |
| 提供文档     | √             |
| v7同步更新   | √             |

### 2. 插件内容

SSO提供统一会话管理，用户只需要登录一次即可访问所有互相信任的系统。

支持**跨域名单点登录**，提供**单点认证服务器**，用户登录可直接经过SSO服务端，也支持客户端登录后再进行统一会话创建。

sso模块维护全局会话，同时维持一个sso数据库

## SaaS多租户插件

### 1. 插件参数

| **插件属性** | **说明**      |
| ------------ | ------------- |
| 适用Guns版本 | Guns v7最新版 |
| 官方认证     | √             |
| 测试通过     | √             |
| 提供文档     | √             |
| v7同步更新   | √             |

### 2. 插件内容

提供基于数据库隔离方式的SAAS多租户运营系统。提供租户创建，不同维度用户的维护，不同维度数据的治理。

## 工作流插件

### 1. 插件参数

| **插件属性** | **说明**      |
| ------------ | ------------- |
| 适用Guns版本 | Guns v7最新版 |
| 官方认证     | √             |
| 测试通过     | √             |
| 提供文档     | √             |
| v7同步更新   | √             |

### 2. 插件内容

| **功能**     | **说明** |
| ------------ | -------- |
| 流程模型管理 | √        |
| 流程设计     | √        |
| 流程部署     | √        |
| 流程导入导出 | √        |
| 流程定义管理 | √        |
| 流程图查看   | √        |
| 流程图映射   | √        |
| 流程配置     | √        |
| 流程分类     | √        |
| 表单配置     | √        |
| 流程脚本     | √        |
| 流程实例管理 | √        |
| 发起流程     | √        |
| 我的待办     | √        |
| 我的已办     | √        |
| 已发流程查看 | √        |

### 3. 插件截图

![img](https://cdn.nlark.com/yuque/0/2022/png/25441324/1658062400672-f9862883-1864-4c30-8a89-dc71a0047517.png)

![img](https://cdn.nlark.com/yuque/0/2022/png/25441324/1658062401818-36be345f-b0a3-4ff3-87ce-0bf01a18232a.png)

![img](https://cdn.nlark.com/yuque/0/2022/png/25441324/1658062401548-01ab405e-24b5-4d14-906f-f44e3ee83128.png)

![img](https://cdn.nlark.com/yuque/0/2022/png/25441324/1658062401612-c60165ff-ab67-4c31-968c-6d6355da496f.png)

![img](https://cdn.nlark.com/yuque/0/2022/png/25441324/1658062401992-803309d8-5b05-4937-9e64-b5d74639f950.png)

## Oracle插件

### 1. 插件参数

| **插件属性** | **说明**      |
| ------------ | ------------- |
| 适用Guns版本 | Guns v7最新版 |
| 官方认证     | √             |
| 测试通过     | √             |
| 提供文档     | √             |
| v7同步更新   | √             |

### 2. 插件内容

1. 包含oracle12的安装过程文档（docker）。
2. 包含连接oracle12的链接方法，包含连接工具的下载。
3. 包含Guns表空间的创建，用户授权的过程。
4. 包含Oracle相关的flyway脚本，一键初始化数据库。
5. 包含程序中对Oracle数据库sql写法的适配。
6. 包含启动不成功的技术指导。

### 3. 插件截图

oracle数据库

![img](https://cdn.nlark.com/yuque/0/2022/png/25441324/1658062877817-e5af65a4-723c-4042-b677-15d01bcc565f.png)

oracle插件内容

![img](https://cdn.nlark.com/yuque/0/2022/png/25441324/1658062875510-303cbfc1-7944-4638-8e03-c1c16cda719e.png)

## PostgreSQL

### 1. 插件参数

| **插件属性** | **说明**      |
| ------------ | ------------- |
| 适用Guns版本 | Guns v7最新版 |
| 官方认证     | √             |
| 测试通过     | √             |
| 提供文档     | √             |
| v7同步更新   | √             |

### 2. 插件内容

1. 包含PostgreSQL12的安装过程文档（docker）。
2. 包含连接PostgreSQL12的链接方法，包含连接工具的下载。
3. 包含PostgreSQL相关的flyway脚本，一键初始化数据库。
4. 包含程序中对PostgreSQL数据库sql写法的适配。
5. 包含启动不成功的技术指导。

### 3. 插件截图

PostgreSQL数据库

![img](https://cdn.nlark.com/yuque/0/2022/png/25441324/1658062939668-4f1e49cc-374b-40d9-ad59-3e5faf3cc216.png)

PostgreSQL插件内容

![img](https://cdn.nlark.com/yuque/0/2022/png/25441324/1658062939212-d09cac57-470e-4ea2-8b84-340a126b99b4.png)

## SqlServer

### 1. 插件参数

| **插件属性** | **说明**      |
| ------------ | ------------- |
| 适用Guns版本 | Guns v7最新版 |
| 官方认证     | √             |
| 测试通过     | √             |
| 提供文档     | √             |
| v7同步更新   | √             |

### 2. 插件内容

1. 包含SqlServer2017的安装过程文档（docker）。
2. 包含连接SqlServer2017的链接方法，包含连接工具的下载。
3. 包含SqlServer2017相关的flyway脚本，一键初始化数据库。
4. 包含程序中对SqlServer2017数据库sql写法的适配。
5. 包含启动不成功的技术指导。

### 3. 插件截图

SqlServer2017数据库

![img](https://cdn.nlark.com/yuque/0/2022/png/25441324/1658062952207-2e5fd885-0a40-4fd9-aeda-815555a195b6.png)

SqlServer2017插件内容

![img](https://cdn.nlark.com/yuque/0/2022/png/25441324/1658062951352-eedbf88c-4a17-498f-9d3f-8587f7582391.png)

## 读写分离——后面都是新的功能

### 1. 插件参数

| **插件属性** | **说明**      |
| ------------ | ------------- |
| 适用Guns版本 | Guns v7最新版 |
| 官方认证     | √             |
| 测试通过     | √             |
| 提供文档     | √             |
| v7同步更新   | √             |

### 2. 解决方案

Guns采用客户端主动负载均衡的模式进行读写分离。数据库信息存放在客户端的连接层，执行sql时，客户端来选择最终的mysql执行服务器。

### 3. 主从同步

主从同步一般如下几种实现方式。

| **方案**                       | **高可用** | **可能丢数据** | **性能** |
| ------------------------------ | ---------- | -------------- | -------- |
| 一主一从（异步复制，手动切换） | 否         | 可控           | 好       |
| 一主一从（异步复制，自动切换） | 是         | 是             | 好       |
| 一主二从（同步复制，自动切换） | 是         | 否             | 差       |

异步复制，可能丢数据，同步复制需要将多个从库同步写完之后才能提交主库的事务，性能差。

一般采用半同步复制的方法，既保证一定的数据安全，又兼顾了性能。

### 4. 插件内容

**1. 包含master slave架构的集群搭建过程。**

**2. 包含mysql主从同步的详细配置。**

**3. 包含Guns v7读写分离插件的集成和配置。**



## 报表插件

### 1. 插件参数

| **插件属性** | **说明**      |
| ------------ | ------------- |
| 适用Guns版本 | Guns v7最新版 |
| 官方认证     | √             |
| 测试通过     | √             |
| 提供文档     | √             |
| v7同步更新   | √             |

### 2. 功能介绍

1. 提供第三方报表组件的集成方式。
2. 提供Excel风格在线报表设计器，提供数据可视化操作。
3. 提供设计报表的在线预览，在线打印和导出等功能。
4. 支持通过sql数据集创建报表操作，支持参数化数据装配过程。
5. 支持复杂表头，数据统计图，计算函数等高级功能的使用。

### 3. 功能截图

![img](https://cdn.nlark.com/yuque/0/2022/png/25441324/1658063710758-d91e9694-b471-4f9d-81d3-a2b0e3412939.png)

![img](https://cdn.nlark.com/yuque/0/2022/png/25441324/1658063710963-5fbbdb9d-37a9-4178-b48f-c27e3a1a742a.png)

![img](https://cdn.nlark.com/yuque/0/2022/png/25441324/1658063710575-7683f750-6a20-47ae-ae3d-97e2afa8d547.png)

### 4. 其他说明

报表组件属于第三方插件所有，本产品不包含对报表组件的最终解释权。



## 持续集成

### 1. 插件参数

| **插件属性** | **说明**      |
| ------------ | ------------- |
| 适用Guns版本 | Guns v7最新版 |
| 官方认证     | √             |
| 测试通过     | √             |
| 提供文档     | √             |
| v7同步更新   | √             |

### 2. 功能介绍

持续集成采用Jenkins中间件 + 全新Blue Ocean插件 + 流水线Pipeline方式配置，Jenkins是一个自动部署、自动发布的工具，在Jenkins上配置好相关Job，之后使用一键部署即可执行一系列的拉取代码、编译代码、自动打包、自动发布到服务器的过程，简化了运维操作，提高了运维效率。

1. 1. 提供Jenkins + Blue Ocean插件安装过程。
   2. 提供Jenkins任务配置以及任务管理文档。
   3. 提供基于部署Guns项目的jenkinsfile相关的配置文件，以及配置过程。

### 3. 功能截图

![img](https://cdn.nlark.com/yuque/0/2022/png/25441324/1658063772660-63444c9c-477c-432b-bafe-be1be9545e55.png)

![img](https://cdn.nlark.com/yuque/0/2022/png/25441324/1658063772779-29c3a5d7-0d90-4d35-80e7-4988e14433b4.png)

![img](https://cdn.nlark.com/yuque/0/2022/png/25441324/1658063772694-5ac1f9ef-5c12-43e5-b384-7b310034d550.png)

![img](https://cdn.nlark.com/yuque/0/2022/png/25441324/1658063772721-27f2a180-24d1-4441-a19d-878e3bea0453.png)

## Skywalking调用链

### 1. 插件参数

| **插件属性** | **说明**      |
| ------------ | ------------- |
| 适用Guns版本 | Guns v7最新版 |
| 官方认证     | √             |
| 测试通过     | √             |
| 提供文档     | √             |
| v7同步更新   | √             |

### 2. 功能介绍

Skywalking是分布式调用链追踪系统，可以监控程序复杂调用链的调用关系，可以监控程序接口的执行路径，使用Skywalking可以方便定位程序的执行效率问题。

1. 1. 提供Skywalking的部署过程。
   2. 提供Guns集成Skywalking Agent的配置过程。
   3. 提供Guns使用Skywalking排查调用链关系的使用教程。

### 3. 功能截图

![img](https://cdn.nlark.com/yuque/0/2022/png/25441324/1658064244593-e40081ac-f726-4859-92ce-f3a2f4727734.png)

## ELK统一日志采集

### 1. 插件参数

| **插件属性** | **说明**      |
| ------------ | ------------- |
| 适用Guns版本 | Guns v7最新版 |
| 官方认证     | √             |
| 测试通过     | √             |
| 提供文档     | √             |
| v7同步更新   | √             |

### 2. 功能介绍

面对多种多样的服务或分布式部署的集群，日志的查询就比较繁琐，使用ELK可以满足我们快速采集不同服务，不同机器日志的需求。

本插件提供如下内容：

1. 1. Elasticsearch、Logstash和Kibana的安装部署过程。
   2. ELK程序的各个组件配置。
   3. Guns接入ELK服务的过程和logback.xml的配置。
   4. Elasticsearch索引配置过程，使用Kibana查看程序实时日志。

### 3. 功能截图

![img](https://cdn.nlark.com/yuque/0/2022/png/25441324/1658064284015-92362c35-45c6-4bed-a72b-39f9828f2a50.png)

## 分布式部署

### 1. 插件参数

| **插件属性** | **说明**      |
| ------------ | ------------- |
| 适用Guns版本 | Guns v7最新版 |
| 官方认证     | √             |
| 测试通过     | √             |
| 提供文档     | √             |
| v7同步更新   | √             |

### 2. 功能介绍

分布式部署指将Guns服务部署在多台服务器，通过Nginx负载均衡的方式部署应用，一方面分摊了单机部署的压力，提高了并发能力，一方面增加了系统的容灾能力。

1. 1. 提供分布式部署的Guns系统改造，例如切换缓存为Redis。
   2. 提供分布式部署的Nginx相关配置。
   3. 提供分布式部署的部署步骤和注意事项。

## 滑动验证码

### 1. 插件参数

| **插件属性** | **说明**      |
| ------------ | ------------- |
| 适用Guns版本 | Guns v7最新版 |
| 官方认证     | √             |
| 测试通过     | √             |
| 提供文档     | √             |
| v7同步更新   | √             |

### 2. 功能介绍

滑动验证码是新型的行为验证方式，只需要用轻轻拖拽滑动到相应位置就可以通过验证，用户体验极佳，同时安全性更高。 滑动验证码简化了用户的操作步骤，简单、快速，相比于图形验证码，大大的增加用户的体验感。

1. 1. 滑动验证码以后端方式生成，并渲染给前端字节数据，确保数据安全。
   2. 滑动验证码由后端校验，校验后再次从新生成，确保验证安全，防止暴力破解。

### 3. 功能截图

![img](https://cdn.nlark.com/yuque/0/2022/png/25441324/1658064746033-1c19faab-c902-4cd3-9541-6c5d051b66cc.png)

## Jar包加密

### 1. 插件参数

| **插件属性** | **说明**      |
| ------------ | ------------- |
| 适用Guns版本 | Guns v7最新版 |
| 官方认证     | √             |
| 测试通过     | √             |
| 提供文档     | √             |
| v7同步更新   | √             |

### 2. 功能介绍

正常Spring Boot打出的jar包或war包，都可以被java反编译工具反编译，获取到java源代码。

当项目交付时，如果不希望客户看到源代码，防止别人反编译源码，可以使用本插件进行Jar包加密处理。

项目jar包加密效果如下，使用反编译工具，无法获取反编译的代码：

![img](https://cdn.nlark.com/yuque/0/2022/png/25441324/1658064735103-77c53735-9e4e-48ba-9979-b7cfcb79e041.png)

## 代码混淆

### 1. 插件参数

| **插件属性** | **说明**      |
| ------------ | ------------- |
| 适用Guns版本 | Guns v7最新版 |
| 官方认证     | √             |
| 测试通过     | √             |
| 提供文档     | √             |
| v7同步更新   | √             |

### 2. 功能介绍

使用jar加密需要特殊的入口程序进行启动程序，那有没有可以直接java -jar启动程序，并且又能保障jar源码安全的方法？

答案是有的，可以使用Guns集成的代码混淆工具，可以一键将已有的jar包进行代码混淆操作。

使用反编译工具时，可以看到jar包源码，但是是被混淆的源码，基本无法读懂，代码混淆后的效果如下，类名和类中代码都已被更改，但项目可以继续正常运行：

![img](https://cdn.nlark.com/yuque/0/2022/png/25441324/1658064943801-3e0a9859-dabd-4b93-b7d0-4d4dc4c9dfe8.png)

## API统一认证

### 1. 插件参数

| **插件属性** | **说明**      |
| ------------ | ------------- |
| 适用Guns版本 | Guns v7最新版 |
| 官方认证     | √             |
| 测试通过     | √             |
| 提供文档     | √             |
| v7同步更新   | √             |

### 2. 功能介绍

API统一认证功能提供了一种外部系统对接Guns系统的一种策略。

适用的场景如下：

1. 外部系统对接Guns系统，需要获取Guns系统的数据。
2. 外部系统对接Guns系统，需要推送数据到Guns系统。

这两个场景都可以使用Guns提供的API统一认证来解决，API统一认证功能制定了一套外部系统访问Guns系统的认证机制，并且可以在线维护这些API客户端，API客户端访问系统需要生成JWT Token，另外数据传输过程中使用非对称加密方式对数据加密，保障数据安全。

![img](https://cdn.nlark.com/yuque/0/2022/png/25441324/1658064952298-1b745a08-9e07-4541-b827-19697441b517.png)

## 临时秘钥

### 1. 插件参数

| **插件属性** | **说明**      |
| ------------ | ------------- |
| 适用Guns版本 | Guns v7最新版 |
| 官方认证     | √             |
| 测试通过     | √             |
| 提供文档     | √             |
| v7同步更新   | √             |

### 2. 功能介绍

临时秘钥功能可以为用户创建一个临时密码，通过后台创建后，可以使用这个密码以指定人的身份登录系统，一般在处理某些业务问题上，会用到临时秘钥。

临时秘钥创建后可以删除但是不能修改，并且可以设置秘钥的过期时间，或者设置秘钥为一次性秘钥，使用秘钥登录完成后就会失效。

![img](https://cdn.nlark.com/yuque/0/2022/png/25441324/1658065440960-12ba7f7a-b630-4788-a97f-a4e320174fe6.png)

## 主题管理

### 1. 插件参数

| **插件属性** | **说明**      |
| ------------ | ------------- |
| 适用Guns版本 | Guns v7最新版 |
| 官方认证     | √             |
| 测试通过     | √             |
| 提供文档     | √             |
| v7同步更新   | √             |

### 2. 功能介绍

主题管理功能可以将页面相关元素（文字或图片）进行在线统一管理，当系统发布时，使用主题管理功能，在线进行修改名称和图案。

主题管理模块分为三个部分：主题属性、主题模板、主题管理。

**主题属性**可以将需要管理的主题配置录入为一个主题属性进行在线管理起来，主题属性可以使字符串类型或者图片类型，例如我们可以录入一个平台名称的属性，管理左上角logo旁边的系统名称。

![img](https://cdn.nlark.com/yuque/0/2022/png/25441324/1658065636195-26f64543-625d-4e9f-a31c-308f38a17ccf.png)

**主题模板**由一组主题属性组成，默认系统中自带一个Guns后台管理系统模板，主题模板相当于一套主题的规则。

![img](https://cdn.nlark.com/yuque/0/2022/png/25441324/1658065635962-6ca06095-fc07-46d0-a416-9ed23fa16c1d.png)

**主题管理**功能相当于模板的实现，在主题管理中，可以真实的设置这些主题属性的值，例如平台名称，平台logo，页脚文字等等。一个系统中可以存在一个模板的多套实现，但是一次只能激活一个主题。

![img](https://cdn.nlark.com/yuque/0/2022/png/25441324/1658065636205-cc6a34d3-19fe-447f-a1a0-2a163c0d4271.png)

## OAuth2登录

### 1. 插件参数

| **插件属性** | **说明**      |
| ------------ | ------------- |
| 适用Guns版本 | Guns v7最新版 |
| 官方认证     | √             |
| 测试通过     | √             |
| 提供文档     | √             |
| v7同步更新   | √             |

### 2. 功能介绍

OAuth2登录功能指Guns以客户端的形式接入到各大第三方平台，从而使用第三方平台账号登录Guns系统。

具体OAuth2的授权流程如下：

 +--------+                               +---------------+      |        |--(A)- Authorization Request ->|   Resource    |      |        |                               |     Owner     |      |        |<-(B)-- Authorization Grant ---|               |      |        |                               +---------------+      |        |      |        |                               +---------------+      |        |--(C)-- Authorization Grant -->| Authorization |      | Client |                               |     Server    |      |        |<-(D)----- Access Token -------|               |      |        |                               +---------------+      |        |      |        |                               +---------------+      |        |--(E)----- Access Token ------>|    Resource   |      |        |                               |     Server    |      |        |<-(F)--- Protected Resource ---|               |      +--------+                               +---------------+ 

将OAuth2秘钥和客户端id等信息配置好之后，点击登录界面的第三方OAuth2图标，

![img](https://cdn.nlark.com/yuque/0/2022/png/25441324/1658067189001-f50820e5-a4c1-480f-bafa-68fb81fd4ad2.png)

点击后将会进入到第三方OAuth2服务端，如果当前没有登录第三方平台的话，会跳转到登录界面，如下：

![img](https://cdn.nlark.com/yuque/0/2022/png/25441324/1658067186681-7b2a9f50-19ad-4b7c-a4aa-734799a91786.png)

输入完账号密码后，点击第三方平台的登录按钮，接着会Redirect到Guns系统，Guns拿到第三方系统的token校验通过后，会直接登录到Guns系统，如下：

![img](https://cdn.nlark.com/yuque/0/2022/png/25441324/1658067185308-f607b162-7c77-4f6e-991d-7d188033e556.png)
