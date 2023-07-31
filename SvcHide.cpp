#include <stdio.h>
#include <windows.h>
#include <sddl.h>

int main() {
    // Nome do serviço a ser configurado
    const wchar_t* serviceName = L"WinHttpSvc";

    // Abrindo o serviço com as permissões necessárias
    SC_HANDLE serviceManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    SC_HANDLE service = OpenService(serviceManager, serviceName, SERVICE_ALL_ACCESS);

    // Definindo as permissões desejadas
    const wchar_t* securityDescriptor = L"D:(D;;DCLCWPDTSD;;;IU)(D;;DCLCWPDTSD;;;SU)(D;;DCLCWPDTSD;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)";
    PSECURITY_DESCRIPTOR sd = nullptr;

    if (ConvertStringSecurityDescriptorToSecurityDescriptor(securityDescriptor, SDDL_REVISION_1, &sd, nullptr)) {
        // Definindo as permissões de segurança
        if (SetServiceObjectSecurity(service, DACL_SECURITY_INFORMATION, sd)) {
            // Permissões definidas com sucesso
            printf("Permissões de segurança definidas com sucesso.\n");
        }
        else {
            // Erro ao definir as permissões de segurança
            printf("Erro ao definir as permissões de segurança do serviço.\n");
        }

        LocalFree(sd);
    }
    else {
        // Erro ao converter o descritor de segurança
        printf("Erro ao converter o descritor de segurança.\n");
    }

    // Fechando os handles do serviço e do gerenciador de serviços
    CloseServiceHandle(service);
    CloseServiceHandle(serviceManager);

    return 0;
}
