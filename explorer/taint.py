import claripy

import logging
logger = logging.getLogger(__name__)

""""
  Annotations are used to achieve claripy's goal of being an arithmetic instrumentation engine.
  They provide a means to pass extra information to the claripy backends.
"""


class AttackerTaintConservative(claripy.Annotation):

    # A nice feature of annotation is that we can actually attach some arguments to it
    # (Name of initial register, address, etc.)
    name = "Unnamed"

    def set_name(self, name):
        self.name = name

    def __str__(self):
        return f'AttackerTaintConservative<{self.name}>'

    @property
    def eliminatable(self):  # pylint:disable=no-self-use
        """
        Returns whether this annotation can be eliminated in a simplification.
        :return: True if eliminatable, False otherwise
        """
        return False  # Let us be conservative for now

    @property
    def relocatable(self):  # pylint:disable=no-self-use
        """
        Returns whether this annotation can be relocated in a simplification.
        :return: True if it can be relocated, false otherwise.
        """
        return True

    def relocate(self, src, dst):  # pylint:disable=no-self-use
        """
        This is called when an annotation has to be relocated because of simplifications.
        Consider the following case:
            x = claripy.BVS('x', 32)
            zero = claripy.BVV(0, 32).add_annotation(your_annotation)
            y = x + zero
        Here, one of three things can happen:
            1. if your_annotation.eliminatable is True, the simplifiers will simply
               eliminate your_annotation along with `zero` and `y is x` will hold
            2. elif your_annotation.relocatable is False, the simplifier will abort
               and y will never be simplified
            3. elif your_annotation.relocatable is True, the simplifier will run,
               determine that the simplified result of `x + zero` will be `x`. It
               will then call your_annotation.relocate(zero, x) to move the annotation
               away from the AST that is about to be eliminated.
        :param src: the old AST that was eliminated in the simplification
        :param dst: the new AST (the result of a simplification)
        :return: the annotation that will be applied to `dst`
        """
        if any(isinstance(a, AttackerTaintConservative) for a in src.annotations):
            new_annotation = self
            # Drop annotation when dst is already tainted
            if any(isinstance(a, AttackerTaintConservative) for a in dst.annotations):
                new_annotation = None
        else:
            # Sanity check: this case should never happen
            raise ValueError(f'Relocating AttackerTaintConservative annotation not in src {src.annotations}')

        return new_annotation


"""
    Same as above, except that eliminatable is set to True (no overtainting). 
"""


class AttackerTaintLiberal(claripy.Annotation):
    """
    The liberal taint is currently not used.
    """
    @property
    def eliminatable(self):
        return True

    @property
    def relocatable(self):
        return True

    def relocate(self, src, dst):
        assert False  # Should never happen


def get_tainted_reg(state, reg_name, size):
    """
    reg_name: name of the register
    size: size (in bits) of the register
    """
    attacker_taint = AttackerTaintConservative()
    attacker_taint.set_name(reg_name)
    return state.solver.BVS(f'{reg_name}_attacker', size,  # key=("{}_attacker".format(reg_name)),
                            uninitialized=True,
                            # annotations=[AttackerTaintLiberal()])
                            annotations = [attacker_taint])


def get_tainted_mem_bits(state, size, annotations=None, **kwargs):
    """
    :param state: State to access the solver with
    :param size: size (in bits) to read
    :param annotations: Optional annotations to additionally add.
    """
    attacker_taint = AttackerTaintConservative()
    # attacker_taint = AttackerTaintLiberal()
    attacker_taint.set_name('memory')
    if annotations:
        annotations.append(attacker_taint)
    else:
        annotations = [attacker_taint]

    return state.solver.BVS('attacker_mem', size,
                            uninitialized=True,
                            annotations=annotations,
                            **kwargs)


def add_taint(bvv):
    return bvv.append_annotation(AttackerTaintConservative())


def is_tainted(expr):
    if type(expr) is int:
        return False
    # elif _has_taint_annotation(expr, AttackerTaintLiberal):
    elif _has_taint_annotation(expr, AttackerTaintConservative):
        return True

    return False


def _has_taint_annotation(expr, taint):
    return _is_immediately_tainted(expr, taint) or any(_is_immediately_tainted(v, taint) for v in expr.leaf_asts())


def _is_immediately_tainted(ast, taint):
    if ast is None:
        return False
    else:
        return any(isinstance(a, taint) for a in ast.annotations)


# def get_tainted_leaves(expr, taint):
#     return list(filter((lambda ast: _is_immediately_tainted(ast, taint)), expr.leaf_asts()))
