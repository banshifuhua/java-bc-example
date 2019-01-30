package com.eamon.bc.chapter01;

import java.security.Provider;
import java.security.Security;

/**
 * @author: eamon
 * @date: 2019-01-30 10:09
 * @description: 列举出 java中已经安装了的 提供者名称和信息
 */
public class ListProviders {
    public static void main(String[] args) {

        Provider[] providers = Security.getProviders();
        for (Provider provider : providers) {
            System.out.println(provider.getName() + " : " + provider.getInfo());
        }
    }
}
