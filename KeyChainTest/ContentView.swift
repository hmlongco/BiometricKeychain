//
//  ContentView.swift
//  KeyChainTest
//
//  Created by Michael Long on 11/23/20.
//

import SwiftUI
import SwiftKeychainWrapper
import LocalAuthentication

struct ContentView: View {

    let keychain = BiometricKeychainWrapper()

    @State var keychainValue: String?
    @State var status: OSStatus = errSecSuccess

    let protectedAccountID = "123e4567e89b12d3a456426652340000"

    init() {
        keychain.set("test", service: "mlong", account: "userID")
        keychain.set("test", service: "jjones", account: "userID")
        print(keychain.keys())
    }

    var body: some View {
        NavigationView {
            Form {
                Section(header: Text("Last Requested Keychain Value")) {
                    Text(currentValue)
                        .foregroundColor(keychainValue == nil ? .secondary : .red)
                        .font(.callout)
                        .frame(maxWidth: .infinity, alignment: .center)
                }
                Section(header: Text("Last Status Code")) {
                    Text("\(status)")
                        .foregroundColor(.secondary)
                        .frame(maxWidth: .infinity, alignment: .center)
                }
                Section {
                    Button("Get Biometric Value") {
                        self.keychainValue = self.keychain.get(service: "biometrics", account: protectedAccountID)
                        self.status = self.keychain.status
                    }
                    Button("Has Biometric Value") {
                        self.keychainValue = self.keychain.has(service: "biometrics", account: protectedAccountID) ? "true" : "false"
                        self.status = self.keychain.status
                    }
                    Button("Set Biometric Value") {
                        let value = "\(UUID())"
                        self.keychain.set(value, service: "biometrics", account: protectedAccountID, options: [.biometricAny])
                        self.status = self.keychain.status
                    }
                    Button("Delete Biometric Value") {
                        self.keychain.delete(service: "biometrics", account: protectedAccountID)
                        self.status = self.keychain.status
                   }
                }
                Section {
                    Button("Get KeyChain Value") {
                        self.keychainValue = self.keychain.get(service: "mlong", account: "password")
                        self.status = self.keychain.status
                    }
                    Button("Has KeyChain Value") {
                        self.keychainValue = self.keychain.has(service: "mlong", account: "password") ? "true" : "false"
                        self.status = self.keychain.status
                    }
                    Button("Set KeyChain Value") {
                        self.keychain.set("secret", service: "mlong", account: "password")
                        self.status = self.keychain.status
                    }
                    Button("Delete Biometric Value") {
                        self.keychain.delete(service: "mlong", account: "password")
                        self.status = self.keychain.status
                   }
                }
            }
            .navigationTitle("Biometric Keychain")
        }
    }

    var currentValue: String {
        if let value = keychainValue {
            return value
        } else if keychain.status.isNotFound {
            return "not found"
        } else if keychain.status.isUserCancelled {
            return "user cancelled"
        } else {
            return " "
        }
    }
}

struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
        ContentView()
    }
}
