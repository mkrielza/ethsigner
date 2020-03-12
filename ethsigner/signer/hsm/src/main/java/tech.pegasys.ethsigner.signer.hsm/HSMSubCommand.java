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
package tech.pegasys.ethsigner.signer.hsm;

import static java.nio.charset.StandardCharsets.UTF_8;

import tech.pegasys.ethsigner.SignerSubCommand;
import tech.pegasys.ethsigner.TransactionSignerInitializationException;
import tech.pegasys.ethsigner.core.signing.SingleTransactionSignerProvider;
import tech.pegasys.ethsigner.core.signing.TransactionSigner;
import tech.pegasys.ethsigner.core.signing.TransactionSignerProvider;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import com.google.common.base.MoreObjects;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Spec;

/** HSM-based authentication related sub-command */
@Command(
    name = HSMSubCommand.COMMAND_NAME,
    description = "Sign transactions with a key stored in an HSM.",
    mixinStandardHelpOptions = true)
public class HSMSubCommand extends SignerSubCommand {

  private static final String READ_PIN_FILE_ERROR = "Error when reading the pin from file.";
  public static final String COMMAND_NAME = "hsm-signer";

  public HSMSubCommand() {}

  @SuppressWarnings("unused") // Picocli injects reference to command spec
  @Spec
  private CommandLine.Model.CommandSpec spec;

  @Option(
      names = {"-l", "--library"},
      description = "The PKCS11 library used to sign transactions.",
      paramLabel = "<LIBRARY_PATH>",
      required = true)
  private Path libraryPath;

  @Option(
      names = {"-s", "--slot-index"},
      description = "The slot housing private keys used to sign transactions.",
      paramLabel = "<SLOT_INDEX>",
      required = true)
  private String slotIndex;

  @Option(
      names = {"-p", "--pin-path"},
      description =
          "Path to a file containing the crypto user pin of the slot housing the private key used to sign transactions.",
      paramLabel = "<PIN_PATH>",
      required = true)
  private Path pinPath;

  @Option(
      names = {"-a", "--eth-address"},
      description = "Ethereum address of account to sign with.",
      paramLabel = "<ETH_ADDRESS>",
      required = true)
  private String ethAddress;

  private TransactionSigner createSigner() throws TransactionSignerInitializationException {
    // return HSMTransactionSignerFactory.createSigner(library, slot, pin);
    final String pin;
    try {
      pin = readPinFromFile(pinPath);
    } catch (final IOException e) {
      throw new TransactionSignerInitializationException(READ_PIN_FILE_ERROR, e);
    }

    // final HSMConfig config = new HSMConfig(keyVaultName, keyName, keyVersion, clientId,
    // clientSecret);

    final HSMTransactionSignerFactory factory =
        new HSMTransactionSignerFactory(
            new HSMKeyStoreProvider(libraryPath.toString(), slotIndex, pin));

    return factory.createSigner(ethAddress);
  }

  @Override
  public TransactionSignerProvider createSignerFactory()
      throws TransactionSignerInitializationException {
    return new SingleTransactionSignerProvider(createSigner());
  }

  @Override
  public String getCommandName() {
    return COMMAND_NAME;
  }

  @Override
  public String toString() {
    return MoreObjects.toStringHelper(this)
        .add("library", libraryPath)
        .add("slot", slotIndex)
        .toString();
  }

  private static String readPinFromFile(final Path path) throws IOException {
    final byte[] fileContent = Files.readAllBytes(path);
    return new String(fileContent, UTF_8);
  }
}
