// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License
// 2.0; you may not use this file except in compliance with the Elastic License
// 2.0.
package org.elasticsearch.xpack.esql.expression.function.scalar.convert;

import java.lang.Override;
import java.lang.String;
import org.elasticsearch.compute.data.Block;
import org.elasticsearch.compute.data.DoubleBlock;
import org.elasticsearch.compute.data.DoubleVector;
import org.elasticsearch.compute.data.LongBlock;
import org.elasticsearch.compute.data.Vector;
import org.elasticsearch.compute.operator.DriverContext;
import org.elasticsearch.compute.operator.EvalOperator;
import org.elasticsearch.core.Releasables;
import org.elasticsearch.xpack.esql.core.InvalidArgumentException;
import org.elasticsearch.xpack.esql.core.tree.Source;

/**
 * {@link EvalOperator.ExpressionEvaluator} implementation for {@link ToUnsignedLong}.
 * This class is generated. Edit {@code ConvertEvaluatorImplementer} instead.
 */
public final class ToUnsignedLongFromDoubleEvaluator extends AbstractConvertFunction.AbstractEvaluator {
  private final EvalOperator.ExpressionEvaluator dbl;

  public ToUnsignedLongFromDoubleEvaluator(Source source, EvalOperator.ExpressionEvaluator dbl,
      DriverContext driverContext) {
    super(driverContext, source);
    this.dbl = dbl;
  }

  @Override
  public EvalOperator.ExpressionEvaluator next() {
    return dbl;
  }

  @Override
  public Block evalVector(Vector v) {
    DoubleVector vector = (DoubleVector) v;
    int positionCount = v.getPositionCount();
    if (vector.isConstant()) {
      try {
        return driverContext.blockFactory().newConstantLongBlockWith(evalValue(vector, 0), positionCount);
      } catch (InvalidArgumentException  e) {
        registerException(e);
        return driverContext.blockFactory().newConstantNullBlock(positionCount);
      }
    }
    try (LongBlock.Builder builder = driverContext.blockFactory().newLongBlockBuilder(positionCount)) {
      for (int p = 0; p < positionCount; p++) {
        try {
          builder.appendLong(evalValue(vector, p));
        } catch (InvalidArgumentException  e) {
          registerException(e);
          builder.appendNull();
        }
      }
      return builder.build();
    }
  }

  private long evalValue(DoubleVector container, int index) {
    double value = container.getDouble(index);
    return ToUnsignedLong.fromDouble(value);
  }

  @Override
  public Block evalBlock(Block b) {
    DoubleBlock block = (DoubleBlock) b;
    int positionCount = block.getPositionCount();
    try (LongBlock.Builder builder = driverContext.blockFactory().newLongBlockBuilder(positionCount)) {
      for (int p = 0; p < positionCount; p++) {
        int valueCount = block.getValueCount(p);
        int start = block.getFirstValueIndex(p);
        int end = start + valueCount;
        boolean positionOpened = false;
        boolean valuesAppended = false;
        for (int i = start; i < end; i++) {
          try {
            long value = evalValue(block, i);
            if (positionOpened == false && valueCount > 1) {
              builder.beginPositionEntry();
              positionOpened = true;
            }
            builder.appendLong(value);
            valuesAppended = true;
          } catch (InvalidArgumentException  e) {
            registerException(e);
          }
        }
        if (valuesAppended == false) {
          builder.appendNull();
        } else if (positionOpened) {
          builder.endPositionEntry();
        }
      }
      return builder.build();
    }
  }

  private long evalValue(DoubleBlock container, int index) {
    double value = container.getDouble(index);
    return ToUnsignedLong.fromDouble(value);
  }

  @Override
  public String toString() {
    return "ToUnsignedLongFromDoubleEvaluator[" + "dbl=" + dbl + "]";
  }

  @Override
  public void close() {
    Releasables.closeExpectNoException(dbl);
  }

  public static class Factory implements EvalOperator.ExpressionEvaluator.Factory {
    private final Source source;

    private final EvalOperator.ExpressionEvaluator.Factory dbl;

    public Factory(Source source, EvalOperator.ExpressionEvaluator.Factory dbl) {
      this.source = source;
      this.dbl = dbl;
    }

    @Override
    public ToUnsignedLongFromDoubleEvaluator get(DriverContext context) {
      return new ToUnsignedLongFromDoubleEvaluator(source, dbl.get(context), context);
    }

    @Override
    public String toString() {
      return "ToUnsignedLongFromDoubleEvaluator[" + "dbl=" + dbl + "]";
    }
  }
}
