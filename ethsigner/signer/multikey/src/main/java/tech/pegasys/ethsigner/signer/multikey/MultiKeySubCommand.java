/*
 * Copyright 2018 ConsenSys AG.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package tech.pegasys.ethsigner.signer.multikey;

import static tech.pegasys.ethsigner.DefaultCommandValues.MANDATORY_PATH_FORMAT_HELP;

import tech.pegasys.ethsigner.KeyGeneratorInitializationException;
import tech.pegasys.ethsigner.SignerSubCommand;
import tech.pegasys.ethsigner.TransactionSignerInitializationException;
import tech.pegasys.ethsigner.core.generation.KeyGeneratorProvider;
import tech.pegasys.ethsigner.core.signing.TransactionSignerProvider;
import tech.pegasys.ethsigner.signer.azure.AzureKeyVaultAuthenticator;
import tech.pegasys.ethsigner.signer.azure.AzureKeyVaultTransactionSignerFactory;
import tech.pegasys.ethsigner.signer.hsm.HSMKeyGeneratorFactory;
import tech.pegasys.ethsigner.signer.hsm.HSMKeyStoreProvider;
import tech.pegasys.ethsigner.signer.hsm.HSMTransactionSignerFactory;

import java.nio.file.Path;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.MoreObjects;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Spec;

/**
 * Multi platform authentication related sub-command. Metadata config TOML files containing signing
 * information from one of several providers.
 */
@Command(
    name = MultiKeySubCommand.COMMAND_NAME,
    description =
        "Access multiple keys (of any supported type). Each key's "
            + "parameters are defined in a separate TOML file contained within a given "
            + "directory.",
    mixinStandardHelpOptions = true)
public class MultiKeySubCommand extends SignerSubCommand {

  public static final String COMMAND_NAME = "multikey-signer";

  public static final String IDENTIFIER_FILE_BASED = "file-based";
  public static final String IDENTIFIER_AZURE = "azure";
  public static final String IDENTIFIER_HSM = "hsm";

  public MultiKeySubCommand() {}

  @SuppressWarnings("unused") // Picocli injects reference to command spec
  @Spec
  private CommandLine.Model.CommandSpec spec;

  @Option(
      names = {"-i", "--identifier"},
      description = "The identifier for the multikey signer to be used",
      required = true,
      paramLabel = "<IDENTIFIER>",
      arity = "1")
  private String identifier;

  @Option(
      names = {"-d", "--directory"},
      description = "The path to a directory containing signing metadata TOML files",
      required = true,
      paramLabel = MANDATORY_PATH_FORMAT_HELP,
      arity = "1")
  private Path directoryPath;

  @Option(
      names = {"-l", "--library"},
      description = "The HSM PKCS11 library used to sign transactions.",
      paramLabel = "<LIBRARY_PATH>",
      required = false)
  private Path libraryPath;

  @Option(
      names = {"-s", "--slot-index"},
      description = "The HSM slot used to sign transactions.",
      paramLabel = "<SLOT_INDEX>",
      required = false)
  private String slotIndex;

  @Option(
      names = {"-p", "--slot-pin"},
      description = "The crypto user pin of the HSM slot used to sign transactions.",
      paramLabel = "<SLOT_PIN>",
      required = false)
  private String slotPin;

  @Override
  public TransactionSignerProvider createSignerFactory()
      throws TransactionSignerInitializationException {
    final SigningMetadataTomlConfigLoader signingMetadataTomlConfigLoader =
        new SigningMetadataTomlConfigLoader(directoryPath);
    switch (identifier) {
      case IDENTIFIER_FILE_BASED:
        {
          return new MultiKeyTransactionSignerProvider(signingMetadataTomlConfigLoader, null, null);
        }
      case IDENTIFIER_AZURE:
        {
          final AzureKeyVaultTransactionSignerFactory azureFactory =
              new AzureKeyVaultTransactionSignerFactory(new AzureKeyVaultAuthenticator());
          return new MultiKeyTransactionSignerProvider(
              signingMetadataTomlConfigLoader, azureFactory, null);
        }
      case IDENTIFIER_HSM:
        {
          final HSMTransactionSignerFactory hsmFactory =
              new HSMTransactionSignerFactory(
                  new HSMKeyStoreProvider(libraryPath.toString(), slotIndex, slotPin));
          return new MultiKeyTransactionSignerProvider(
              signingMetadataTomlConfigLoader, null, hsmFactory);
        }
    }
    throw new TransactionSignerInitializationException("Incorrect identifier");
  }

  @Override
  public KeyGeneratorProvider createGeneratorFactory() throws KeyGeneratorInitializationException {
    switch (identifier) {
      case IDENTIFIER_FILE_BASED:
      case IDENTIFIER_AZURE:
        {
          return null;
        }
      case IDENTIFIER_HSM:
        {
          return new HSMKeyGeneratorFactory(
              new HSMKeyStoreProvider(libraryPath.toString(), slotIndex, slotPin), directoryPath);
        }
    }
    throw new KeyGeneratorInitializationException("Incorrect identifier");
  }

  @Override
  public String getCommandName() {
    return COMMAND_NAME;
  }

  @VisibleForTesting
  Path getDirectoryPath() {
    return directoryPath;
  }

  @Override
  public String toString() {
    return MoreObjects.toStringHelper(this).add("directoryPath", directoryPath).toString();
  }
}
