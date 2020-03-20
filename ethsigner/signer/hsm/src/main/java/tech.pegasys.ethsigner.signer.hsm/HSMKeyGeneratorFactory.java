/*
 * Copyright 2019 ConsenSys AG.
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

import tech.pegasys.ethsigner.core.generation.KeyGeneratorProvider;

import java.nio.file.Path;

public class HSMKeyGeneratorFactory implements KeyGeneratorProvider {

  private final HSMKeyStoreProvider provider;
  private final Path directory;

  public HSMKeyGeneratorFactory(final HSMKeyStoreProvider provider, final Path directory) {
    this.provider = provider;
    this.directory = directory;
  }

  @Override
  public HSMKeyGenerator getGenerator() {
    return new HSMKeyGenerator(provider);
  }

  @Override
  public Path getDirectory() {
    return directory;
  }
}
