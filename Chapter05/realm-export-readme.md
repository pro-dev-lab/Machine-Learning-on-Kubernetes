
### Json comment

``` bash
{
  "id": "master",  // Realm의 내부 ID (보통 realm 이름과 동일)
  "realm": "master",  // 현재 Realm 이름 (기본적으로 master)
  "displayName": "Keycloak",  // 관리 콘솔에서 표시될 Realm의 이름
  "displayNameHtml": "<div class=\"kc-logo-text\"><span>Keycloak</span></div>",  // HTML 형식의 표시 이름

  // 토큰과 세션의 만료 및 인증 관련 설정
  "notBefore": 1640611320,  // 모든 토큰이 이 시간 이후에만 유효
  "defaultSignatureAlgorithm": "RS256",  // 기본적으로 사용하는 JWT 서명 알고리즘
  "revokeRefreshToken": false,  // Refresh Token을 철회할 것인지 여부
  "refreshTokenMaxReuse": 0,  // Refresh Token 재사용 허용 횟수
  "accessTokenLifespan": 60,  // 액세스 토큰 만료 시간 (초)
  "accessTokenLifespanForImplicitFlow": 900,  // Implicit Flow 사용 시 토큰 수명
  "ssoSessionIdleTimeout": 1800,  // SSO 세션 유휴 타임아웃 (초)
  "ssoSessionMaxLifespan": 36000,  // SSO 세션 최대 수명 (초)
  "offlineSessionIdleTimeout": 2592000,  // 오프라인 세션 유휴 타임아웃 (초)
  "offlineSessionMaxLifespanEnabled": false,  // 오프라인 세션 최대 수명 제한 활성화 여부
  "offlineSessionMaxLifespan": 5184000,  // 오프라인 세션 최대 수명 (초)

  // 인증 관련 정책 설정
  "sslRequired": "external",  // 외부 연결에서만 SSL 필수
  "registrationAllowed": false,  // 사용자 직접 등록 허용 여부
  "rememberMe": false,  // "기억하기" 옵션 허용 여부
  "verifyEmail": false,  // 이메일 인증 필요 여부
  "loginWithEmailAllowed": true,  // 이메일 로그인 허용 여부

  // 보안 관련 설정
  "bruteForceProtected": false,  // Brute-force 보호 활성화 여부
  "failureFactor": 30,  // 실패 임계값 (이 값 초과 시 계정 잠금)
  "roles": {  // 역할(Role) 정의
    "realm": [
      {
        "id": "ae022404-8273-4f0d-aa7d-6e827653106f",
        "name": "admin",  // 관리자 역할 정의
        "description": "${role_admin}",
        "composite": true,  // 복합 역할 여부
        "composites": {
          "realm": ["create-realm"],  // 이 역할이 포함하는 다른 역할
          "client": {
            "master-realm": [
              "create-client",
              "manage-identity-providers",
              "query-users",
              "view-events",
              "impersonation",
              "manage-realm",
              "view-users",
              "manage-events",
              "view-clients",
              "query-realms",
              "manage-users",
              "view-realm"
            ]
          }
        }
      }
    ]
  },

  // 클라이언트 정의 (Keycloak에 등록된 애플리케이션)
  "clients": [
    {
      "id": "bf7316d9-b83d-43da-8c1d-ab01bfe537b8",
      "clientId": "aflow",  // Airflow 클라이언트
      "enabled": true,  // 활성화 여부
      "publicClient": true,  // 공개 클라이언트 여부 (비밀번호 없이 로그인 가능)
      "protocol": "openid-connect",  // 사용 프로토콜 (OIDC)
      "redirectUris": ["*"],  // 허용되는 리디렉션 URI
      "attributes": {  // 추가 속성
        "use.refresh.tokens": "true",
        "require.pushed.authorization.requests": "false"
      }
    },
    {
      "id": "d1e16d02-d90c-4452-a217-07fb20847e44",
      "clientId": "grafana",  // Grafana 클라이언트
      "enabled": true,
      "publicClient": true,
      "protocol": "openid-connect",
      "redirectUris": ["*"],
      "attributes": {
        "use.refresh.tokens": "true"
      }
    }
  ],

  // 그룹(Group) 정의
  "groups": [
    {
      "id": "0d07dcb4-70d8-4906-b7de-680d2199b708",
      "name": "ml-group",  // 머신러닝 관련 그룹
      "clientRoles": {
        "grafana": ["admin"],
        "aflow": ["admin"],
        "jhub": ["admin"],
        "mflow": ["admin"]
      }
    }
  ],

  // 사용자 프로파일 업데이트 요구사항
  "requiredActions": [
    {
      "alias": "CONFIGURE_TOTP",
      "name": "Configure OTP",
      "enabled": true
    },
    {
      "alias": "UPDATE_PASSWORD",
      "name": "Update Password",
      "enabled": true
    },
    {
      "alias": "VERIFY_EMAIL",
      "name": "Verify Email",
      "enabled": true
    }
  ],

  // 브라우저 로그인 흐름
  "browserFlow": "browser",

  // 인증 흐름 정의
  "authenticationFlows": [
    {
      "id": "955621da-81d6-4f28-8f6e-c59bb4bb46a6",
      "alias": "browser",
      "description": "브라우저 기반 인증",
      "authenticationExecutions": [
        {
          "authenticator": "auth-cookie",
          "requirement": "ALTERNATIVE"
        },
        {
          "authenticator": "identity-provider-redirector",
          "requirement": "ALTERNATIVE"
        },
        {
          "authenticatorFlow": true,
          "flowAlias": "forms",
          "requirement": "ALTERNATIVE"
        }
      ]
    }
  ],

  // SMTP 설정 (이메일 발송 관련)
  "smtpServer": {},

  // 이벤트 로깅 관련 설정
  "eventsEnabled": false,
  "adminEventsEnabled": false
}

```
![image](https://github.com/user-attachments/assets/58117dbc-fdad-4f52-8ffe-8aa02f8faa5a)

* 나머지 디폴트 설정은 일부 설정 값들이 Keycloak의 기본값이거나 특정 기능이 활성화되지 않은 상태를 나타냄. 그러나 필요할 수도 있으므로 아래와 같이 설명을 정리
  ![image](https://github.com/user-attachments/assets/423cb73a-f90a-45c0-88cb-a1587ea2a0ff)
  ![image](https://github.com/user-attachments/assets/1aa2c997-9c51-4036-94a2-be0f04eb6060)
  ![image](https://github.com/user-attachments/assets/f90bf595-cc03-4109-a61e-965043034a7b)


