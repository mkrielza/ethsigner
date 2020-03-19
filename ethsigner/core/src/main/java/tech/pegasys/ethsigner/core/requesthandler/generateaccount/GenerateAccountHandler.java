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
package tech.pegasys.ethsigner.core.requesthandler.generateaccount;

import tech.pegasys.ethsigner.core.generation.KeyGeneratorProvider;
import tech.pegasys.ethsigner.core.http.HttpResponseFactory;
import tech.pegasys.ethsigner.core.jsonrpc.JsonRpcRequest;
import tech.pegasys.ethsigner.core.jsonrpc.response.JsonRpcSuccessResponse;
import tech.pegasys.ethsigner.core.requesthandler.JsonRpcRequestHandler;

import io.netty.handler.codec.http.HttpResponseStatus;
import io.vertx.ext.web.RoutingContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class GenerateAccountHandler implements JsonRpcRequestHandler {

  private static final Logger LOG = LogManager.getLogger();

  private final KeyGeneratorProvider keyGeneratorProvider;
  private final HttpResponseFactory responder;

  public GenerateAccountHandler(
      final KeyGeneratorProvider keyGeneratorProvider, final HttpResponseFactory responder) {
    this.keyGeneratorProvider = keyGeneratorProvider;
    this.responder = responder;
  }

  @Override
  public void handle(final RoutingContext context, final JsonRpcRequest request) {
    LOG.debug("Generating account request {}, {}", request.getId(), request.getMethod());
    final String address = keyGeneratorProvider.getGenerator().generate();
    final JsonRpcSuccessResponse response = new JsonRpcSuccessResponse(request.getId(), address);
    responder.create(context.request(), HttpResponseStatus.OK.code(), response);
  }
}
