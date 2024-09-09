# Java SAML SP Sample

### 개요
SAML 흐름과 request, response의 형태 및 연동 과정을 좀 더 쉽게 이해하기위해 샘플 프로젝트를 만들었습니다.  
프로젝트의 class들은 역할 구분 없이 하나의 패키지로 구성했습니다.  

### 예제 SAML SSO 케이스 - SP-Initiated SSO : Redirect/POST Bindings
SAML 여러 사용 케이스 중 SP-Initiated SSO : Redirect/POST Bindings 테스트 가능합니다.  
* SP -> IDP : Redirect  
* IDP -> SP : POST  

### 실행 환경

- Java 11+

### 설정 하기 ( application.yml )
```yml
~~~~
sp:
  entity_id: [사용할 엔티티 아이디]
  single_sign_on_service_location: [IDP SAML 로그인 URL]
  single_logout_service_location: [IDP SAML 로그아웃 URL]
  acs: /acs # assertion customer service url
  login_url: /sso/saml2
~~~~
```

### 연동 하기 ( SSO Server 관리자페이지 )

#### 1. 연동시스템 엔티티 아이디
- application.yml의 entity_id 입력

#### 2. 응답형식
- 응답서명 알고리즘 : RSA-SHA1
- 응답 아이디 형식 : 일회성
- 응답 아이디 구분 : 조회
- 응답 아이디 조회 SQL : SELECT ~

#### 3. 로그인 정보
- 로그인 프로토콜 : HTTP POST
- 로그인 URL : `http://localhost:9106/acs`
- SSO URL : ??

#### 4. 로그아웃 정보
- 로그아웃 프로토콜 : HTTP Redirect
- 로그아웃 URL : `http://localhost:9106/out`
- 로그아웃 요청 URL : ??

#### 5. 라이선스
- agent 라이선스 생성

### 실행 하기

#### 1. Service Provider 실행

- SamlSpApplication Main 메소드 debug로 실행

#### 2. [Service provider - http://localhost:9106/main](http://localhost:9106/main) 접속

- 로그인 클릭

#### 3. Identity Provider 통합 로그인 페이지에서 ID/PWD 입력해 로그인

- ( IDP에 사용자 등록 필요 )

#### 4. 인증 성공

- SP AuthnRequest, IDP Response 확인

### Service Provider 주요 클래스

- SamlSpApplication : SP main 메소드, saml 초기화, Controller class 포함 
- SamlAssertionConsumeFilter : Assertion consume url 처리 필터, AbstractAuthenticationProcessingFilter 확장 클래스
- SimpleSamlAssertionConsumer : SAML Response 검증 후 UserDetails 생성
- SamlSsoEntryPoint : SAML Request redirect, AuthenticationEntryPoint 구현
- SamlLogoutHandler : SAML 로그아웃, IDP에 LogoutRequest 전송 후 SP session 삭제

### Reference

- [OASIS Doc](http://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-tech-overview-2.0.html)
- [pac4j](https://github.com/pac4j/pac4j)